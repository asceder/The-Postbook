
///////////////////////////////////////////////////////////////////////////////////
//  FEEDBACK API ENDPOINT SERVER
//  AHMED S CEDER 
//  (c) 2024-2025
//  Email <ahmed.ceder@gmail.com>
//  Farmingdale, NY 11735 
///////////////////////////////////////////////////////////////////////////////////


const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mariadb = require('mariadb');
const bcrypt = require('bcryptjs');
const app = express();
const port = 3000;

const jwt = require('jsonwebtoken');
const SECRET_KEY = 'p?oG1&r,1=ac5I%`="&}v4Jq'; // Replace with a strong secret key


app.use(express.json());

// Database connection
const pool = mariadb.createPool({
  host: 'localhost', 
  user: 'feedback', 
  password: 'abc123@#', 
  database: 'feedback_db',
  connectionLimit: 5
});


// Test the connection
(async () => {
  let conn;
  try {
    conn = await pool.getConnection();
    console.log('SQL Database connection was Established!');
  } catch (err) {
    console.error('SQL Database connection failed:', err);
  } finally {
    if (conn) conn.release(); // Release the connection back to the pool
  }
})();



// Multer setup for photo upload


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads'); // Directory to save files
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true }); // Create folder if it doesn't exist
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`; // Generate unique file name
    cb(null, uniqueName);
  },
});


const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images are allowed.'), false);
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 }, // 5MB limit
});



// Serve the uploads folder as a static resource
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// Login Endpoint 

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const conn = await pool.getConnection();
    const result = await conn.query(`SELECT * FROM user_table WHERE email = ?`, [email]);
    conn.release();

    if (result.length === 0) {
      return res.status(403).send({ success: false, message: 'Invalid email or password' });
    }

    const user = result[0];

    // Compare hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(403).send({ success: false, message: 'Invalid email or password' });
    }

    // Generate JWT Token
    const token = jwt.sign({ uid: user.uid, email: user.email }, SECRET_KEY, { expiresIn: '2h' });

    res.status(200).send({
      success: true,
      message: 'Login successful',
      token,
      user: {
        uid: user.uid,
        name: user.name,
        email: user.email,
        phone_country_code: user.phone_country_code,
        phone_actual: user.phone_actual
      }
    });

  } catch (err) {
    res.status(500).send({ success: false, message: 'An error occurred during authentication', error: err.message });
  }
});


// REGISTER NEW USER
//
//


app.post('/register', async (req, res) => {
  const { name, email, phone_country_code, phone_actual, password } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password with salt
    const conn = await pool.getConnection();
    await conn.query(
      `INSERT INTO user_table (name, email, phone_country_code, phone_actual, password) VALUES (?, ?, ?, ?, ?)`,
      [name, email, phone_country_code, phone_actual, hashedPassword]
    );
    conn.release();

    res.status(201).send({ success: true, message: 'User registered successfully' });
  } catch (err) {
    res.status(500).send({ success: false, message: 'Error registering user', error: err.message });
  }
});

//AUTHENICATION MIDDLEWARE
//
//
//

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send({ success: false, message: 'Access denied. No token provided.' });

  jwt.verify(token.replace('Bearer ', ''), SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send({ success: false, message: 'Invalid token' });

    req.user = user;
    next();
  });
};


// FOR PROTECTED ROUTES
//
app.get('/protected-route', authenticateToken, (req, res) => {
  res.send({ message: 'You have access to this protected route.', user: req.user });
});



//USER ENDPOINTS

// Create User
app.post('/user', async (req, res) => {
  const { name, email, phone_country_code, phone_actual, password } = req.body;
  const encryptedPassword = await bcrypt.hash(password, 10);
  const member_since = new Date();

  try {
    const conn = await pool.getConnection();
    const result = await conn.query(
      `INSERT INTO user_table (name, email, phone_country_code, phone_actual, password, member_since) VALUES (?, ?, ?, ?, ?, ?)`,
      [name, email, phone_country_code, phone_actual, encryptedPassword, member_since]
    );
    conn.release();
    res.status(201).send({ message: 'User created successfully', uid: result.insertId });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

// Read User
//
//

app.get('/user/:uid', async (req, res) => {
  const { uid } = req.params;
  try {
    const conn = await pool.getConnection();
    const result = await conn.query(`SELECT uid, name, email, phone_country_code, phone_actual, member_since, photo FROM user_table WHERE uid = ?`, [uid]);
    conn.release();
    if (result.length === 0) {
      res.status(404).send({ message: 'User not found' });
    } else {
      res.status(200).send(result[0]);
    }
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

// Update User
app.put('/user/:uid', async (req, res) => {
  const { uid } = req.params;
  const { name, email, phone_country_code, phone_actual, password } = req.body;
  const encryptedPassword = password ? await bcrypt.hash(password, 10) : null;
  const update_date = new Date();

  try {
    const conn = await pool.getConnection();
    const existingUser = await conn.query(`SELECT * FROM user_table WHERE uid = ?`, [uid]);

    if (existingUser.length === 0) {
      conn.release();
      res.status(404).send({ message: 'User not found' });
      return;
    }

    const result = await conn.query(
      `UPDATE user_table SET name = ?, email = ?, phone_country_code = ?, phone_actual = ?, password = ?  WHERE uid = ?`,
      [
        name || existingUser[0].name,
        email || existingUser[0].email,
        phone_country_code || existingUser[0].phone_country_code,
        phone_actual || existingUser[0].phone_actual,
        encryptedPassword || existingUser[0].password,
    //    update_date,
        uid
      ]
    );
    conn.release();
    res.status(200).send({ message: 'User updated successfully' });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

// Delete User
app.delete('/user/:uid', async (req, res) => {
  const { uid } = req.params;
  try {
    const conn = await pool.getConnection();
    const result = await conn.query(`DELETE FROM user_table WHERE uid = ?`, [uid]);
    conn.release();
    if (result.affectedRows === 0) {
      res.status(404).send({ message: 'User not found' });
    } else {
      res.status(200).send({ message: 'User deleted successfully' });
    }
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});



// Feedback Post CRUD APIs

app.post('/feedback', upload.single('photo'), async (req, res) => {
  const {
    title_of_post,
    category,
    loc_latitude,
    loc_longitude,
    userid,
    camera_latitude,
    camera_longitude,
    post_description,
    sub_category,
    popularity
  } = req.body;

  const fileName = req.file ? req.file.filename : null;
  const fileUrl = req.file ? `/uploads/${fileName}` : null; // Assuming your server serves files from /uploads
  const date_created = new Date();

  try {
    const conn = await pool.getConnection();
    const result = await conn.query(
      `INSERT INTO feedback_post_table (title_of_post, photo, category, date_created, loc_latitude, loc_longitude, userid, camera_latitude, camera_longitude, post_description, sub_category, popularity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        title_of_post,
	fileUrl, // Save the file URL in the photo field
        category,
        date_created,
        loc_latitude,
        loc_longitude,
        userid,
        camera_latitude,
        camera_longitude,
        post_description,
        sub_category,
        popularity
      ]
    );
    conn.release();
    res.status(201).send({
      message: 'Feedback post created successfully',
      //fbid: result.insertId,
    	fbid: result.insertId.toString(), // Convert BigInt to string
    });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});


// Read Feedback Post
app.get('/feedback/:fbid', async (req, res) => {
  const { fbid } = req.params;
  try {
    const conn = await pool.getConnection();
    const result = await conn.query(`SELECT * FROM feedback_post_table WHERE fbid = ?`, [fbid]);
    conn.release();
    if (result.length === 0) {
      res.status(404).send({ message: 'Feedback post not found' });
    } else {
      res.status(200).send(result[0]);
    }
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});


// Additional 
//
// API to fetch all feedback posts

app.get('/feedbacks', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    
    // Query to fetch all feedback posts
    const result = await conn.query(`
      SELECT 
        fbid, 
        title_of_post,
	photo, 
        category, 
        date_created, 
        date_updated, 
        loc_latitude, 
        loc_longitude, 
        userid, 
        camera_latitude, 
        camera_longitude, 
        post_description, 
        sub_category, 
        popularity 
      FROM feedback_post_table
    `);

    conn.release();

    // Check if any posts exist
    if (result.length === 0) {
      res.status(404).send({ message: 'No feedback posts found' });
    } else {
      res.status(200).send(result);
    }
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});


app.put('/update-feedback/:fbid', upload.single('photo'), async (req, res) => {
  const { fbid } = req.params; // Feedback ID to update
  const {
    title_of_post,
    category,
    loc_latitude,
    loc_longitude,
    userid,
    camera_latitude,
    camera_longitude,
    post_description,
    sub_category,
    popularity
  } = req.body;

  const fileName = req.file ? req.file.filename : null;
  const fileUrl = req.file ? `/uploads/${fileName}` : null; // New photo URL if a file is uploaded

  try {
    const conn = await pool.getConnection();

    // Get the existing record to check if the photo field needs updating
    const [existingRecord] = await conn.query(
      `SELECT photo FROM feedback_post_table WHERE fbid = ?`,
      [fbid]
    );

    if (!existingRecord) {
      conn.release();
      return res.status(404).send({ error: 'Feedback post not found' });
    }

    // If no new photo is uploaded, retain the existing photo URL
    const updatedPhotoUrl = fileUrl || existingRecord.photo;

    // Update the record in the database
    const result = await conn.query(
      `UPDATE feedback_post_table
       SET 
         photo = ?,
         title_of_post = COALESCE(?, title_of_post),
	 category = COALESCE(?, category),
         loc_latitude = COALESCE(?, loc_latitude),
         loc_longitude = COALESCE(?, loc_longitude),
         userid = COALESCE(?, userid),
         camera_latitude = COALESCE(?, camera_latitude),
         camera_longitude = COALESCE(?, camera_longitude),
         post_description = COALESCE(?, post_description),
         sub_category = COALESCE(?, sub_category),
         popularity = COALESCE(?, popularity)
       WHERE fbid = ?`,
      [
        updatedPhotoUrl,
        title_of_post,
	category,
        loc_latitude,
        loc_longitude,
        userid,
        camera_latitude,
        camera_longitude,
        post_description,
        sub_category,
        popularity,
        fbid,
      ]
    );

    conn.release();

    res.status(200).send({
      message: 'Feedback post updated successfully',
      affectedRows: result.affectedRows,
    });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});


// Delete Feedback Post
app.delete('/feedback/:fbid', async (req, res) => {
  const { fbid } = req.params;
  try {
    const conn = await pool.getConnection();
    const result = await conn.query(`DELETE FROM feedback_post_table WHERE fbid = ?`, [fbid]);
    conn.release();
    if (result.affectedRows === 0) {
      res.status(404).send({ message: 'Feedback post not found' });
    } else {
      res.status(200).send({ message: 'Feedback post deleted successfully' });
    }
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});


// Category CRUD APIs

// Create Category
app.post('/category', async (req, res) => {
    const { cat_value } = req.body;
    try {
      const conn = await pool.getConnection();
      const result = await conn.query(`INSERT INTO category_details_table (cat_value) VALUES (?)`, [cat_value]);
      conn.release();
      res.status(201).send({ message: 'Category created successfully', cat_id: result.insertId });
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  
  // Read Category
  app.get('/category/:cat_id', async (req, res) => {
    const { cat_id } = req.params;
    try {
      const conn = await pool.getConnection();
      const result = await conn.query(`SELECT * FROM category_details_table WHERE cat_id = ?`, [cat_id]);
      conn.release();
      if (result.length === 0) {
        res.status(404).send({ message: 'Category not found' });
      } else {
        res.status(200).send(result[0]);
      }
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  

// Endpoint to fetch all categorie items without selection
app.get('/categories', async (req, res) => {
  try {
    const conn = await pool.getConnection(); // Get a connection from the pool
    const result = await conn.query(`SELECT * FROM category_details_table`); // Query all categories
    conn.release(); // Release the connection back to the pool

    if (result.length === 0) {
      res.status(404).send({ success: false, message: 'No categories found.' });
    } else {
      res.status(200).send({ success: true, data: result });
    }
  } catch (err) {
    res.status(500).send({
      success: false,
      message: 'An error occurred while fetching categories.',
      error: err.message,
    });
  }
}); 


// Update Category
  app.put('/category/:cat_id', async (req, res) => {
    const { cat_id } = req.params;
    const { cat_value } = req.body;
    try {
      const conn = await pool.getConnection();
      const existingCategory = await conn.query(`SELECT * FROM category_details_table WHERE cat_id = ?`, [cat_id]);
  
      if (existingCategory.length === 0) {
        conn.release();
        res.status(404).send({ message: 'Category not found' });
        return;
      }
  
      await conn.query(`UPDATE category_details_table SET cat_value = ? WHERE cat_id = ?`, [cat_value, cat_id]);
      conn.release();
      res.status(200).send({ message: 'Category updated successfully' });
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  
  // Delete Category
  app.delete('/category/:cat_id', async (req, res) => {
    const { cat_id } = req.params;
    try {
      const conn = await pool.getConnection();
      const result = await conn.query(`DELETE FROM category_details_table WHERE cat_id = ?`, [cat_id]);
      conn.release();
      if (result.affectedRows === 0) {
        res.status(404).send({ message: 'Category not found' });
      } else {
        res.status(200).send({ message: 'Category deleted successfully' });
      }
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  
  // Sub-Category CRUD APIs
  
  // Create Sub-Category
  app.post('/subcategory', async (req, res) => {
    const { sub_cat_value } = req.body;
    try {
      const conn = await pool.getConnection();
      const result = await conn.query(`INSERT INTO sub_category_table (sub_cat_value) VALUES (?)`, [sub_cat_value]);
      conn.release();
      res.status(201).send({ message: 'Sub-Category created successfully', sub_cat_id: result.insertId });
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  
  // Read Sub-Category
  app.get('/subcategory/:sub_cat_id', async (req, res) => {
    const { sub_cat_id } = req.params;
    try {
      const conn = await pool.getConnection();
      const result = await conn.query(`SELECT * FROM sub_category_table WHERE sub_cat_id = ?`, [sub_cat_id]);
      conn.release();
      if (result.length === 0) {
        res.status(404).send({ message: 'Sub-Category not found' });
      } else {
        res.status(200).send(result[0]);
      }
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  

   // Endpoint to fetch all subcategories
 app.get('/subcategories', async (req, res) => {
  try {
    const conn = await pool.getConnection(); // Get a connection from the pool
    const result = await conn.query(`SELECT * FROM sub_category_table`); // Query all subcategories
    conn.release(); // Release the connection back to the pool

    if (result.length === 0) {
      res.status(404).send({ success: false, message: 'No subcategories found.' });
    } else {
      res.status(200).send({ success: true, data: result });
    }
  } catch (err) {
    res.status(500).send({
      success: false,
      message: 'An error occurred while fetching subcategories.',
      error: err.message,
    });
  }
});

  // Update Sub-Category
  app.put('/subcategory/:sub_cat_id', async (req, res) => {
    const { sub_cat_id } = req.params;
    const { sub_cat_value } = req.body;
    try {
      const conn = await pool.getConnection();
      const existingSubCategory = await conn.query(`SELECT * FROM sub_category_table WHERE sub_cat_id = ?`, [sub_cat_id]);
  
      if (existingSubCategory.length === 0) {
        conn.release();
        res.status(404).send({ message: 'Sub-Category not found' });
        return;
      }
  
      await conn.query(`UPDATE sub_category_table SET sub_cat_value = ? WHERE sub_cat_id = ?`, [sub_cat_value, sub_cat_id]);
      conn.release();
      res.status(200).send({ message: 'Sub-Category updated successfully' });
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  

  // Delete Sub-Category

  app.delete('/subcategory/:sub_cat_id', async (req, res) => {
    const { sub_cat_id } = req.params;
    try {
      const conn = await pool.getConnection();
      const result = await conn.query(`DELETE FROM sub_category_table WHERE sub_cat_id = ?`, [sub_cat_id]);
      conn.release();
      if (result.affectedRows === 0) {
        res.status(404).send({ message: 'Sub-Category not found' });
      } else {
        res.status(200).send({ message: 'Sub-Category deleted successfully' });
      }
    } catch (err) {
      res.status(500).send({ error: err.message });
    }
  });
  
  // Start the server
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
  

// API Endpoint: Upload user photo
app.post('/upload-user-photo/:uid', upload.single('photo'), async (req, res) => {
    const { uid } = req.params;

    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }

    try {
        const photoUrl = `/uploads/user_photos/${req.file.filename}`;

        const conn = await pool.getConnection();
        await conn.query('UPDATE user_table SET photo = ? WHERE uid = ?', [photoUrl, uid]);
        conn.release();

        res.status(200).json({ success: true, message: 'Photo uploaded successfully.', photoUrl });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error uploading photo.', error: error.message });
    }
});




