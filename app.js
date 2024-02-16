const express = require('express'); 
const { Pool } = require('pg'); 
const bodyParser = require('body-parser'); 
const bcrypt = require('bcrypt'); 

const app = express(); 
const port = 3000; 

const pool = new Pool({ 
   user: 'postgres', 
   host: 'localhost', 
   database: 'postgres', 
   password: '1908', 
   port: 5432, 
}); 

app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json());

// Middleware for request logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Middleware for error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// Middleware for authentication
const authenticateUser = async (req, res, next) => {
  // Implement your authentication logic here
  // For example, check if the user is logged in using sessions or tokens
  next();
};

//--Role Authorization Middleware---
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      return next();
    } else if (req.admin && req.admin.role === role) {
      return next();
    } else if (req.moderator && req.moderator.role === role) {
      return next();
    } else {
      return res.status(403).json({message: "Unauthorized"});
    }
  };
};

app.use((req, res, next) => {
  req.user = {role: "user"};
  next();
});

app.use((req, res, next) => {
  req.admin = {role: "admin"};
  next();
}); 

app.use((req, res, next) => {
  req.moderator = {role: "moderator"};
  next();
});

//-----Admin Routes-------
app.get('/admin', authorizeRole("admin"), (req, res) => { 
  res.sendFile(__dirname + '/admin_page.html'); 
});

//-----Moderator Routes-----
app.get('/moderator', authorizeRole("moderator"), (req, res) => { 
  res.sendFile(__dirname + '/moderator_page.html'); 
});

//------User Routes-------
app.get('/user', authorizeRole("user"), (req, res) => { 
  res.sendFile(__dirname + '/user_page.html');
});

//-----Sign Up------
app.get('/', (req, res) => { 
  res.sendFile(__dirname + '/index.html'); 
});

app.post('/api/auth/signup', async (req, res) => { 
   const { username, email, password, role } = req.body; 
   
// Hash the password 
const hashedPassword = await bcrypt.hash(password, 10); 

// Insert user into the database 
try {
   // Check if the username or email already exists
   const userCheck = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);

    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    // Insert user into the database
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [username, email, hashedPassword, role]
    );
    res.redirect('/signIn');
} catch (error) {
   console.error(error);
   res.status(500).send('Error registering user');
 }
}); 

//-----Sign In------
app.get('/signIn', (req, res) => { 
  res.sendFile(__dirname + '/signIn.html'); 
}); 

app.post('/api/auth/signin', async (req, res) => { 
  const { username, password } = req.body; 

try {
   const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

   if (result.rows.length === 1) {
     const user = result.rows[0];
     const passwordMatch = await bcrypt.compare(password, user.password);

     if (passwordMatch) {
       if (user.role === 'admin') {
         res.redirect('/admin');
       } else if (user.role === 'moderator') {
         res.redirect('/moderator');
       } else {
         res.redirect('/user');
       }
     }else {
       res.status(401).json({ message: 'Invalid password' });
     }
   } else {
     res.status(404).json({ message: 'User not found' });
   }
 } catch (error) {
   console.error(error);
   res.status(500).send('Error during login');
 }
});

//----Admin's Button Add User--------
app.post('/admin/addUser', authorizeRole("admin"), async (req, res) => {
  try {
    const { username, email, password, role} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [username, email, hashedPassword, role]
    );

    res.status(201).json({message: 'User added successfully', user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({message: 'Error adding user to the database' });
  }
});

//----Admin's Button Delete User--------
app.delete('/api/admin/deleteuser', async (req, res) => {
  try {
    const { userIdToDelete } = req.body;
    const query = 'DELETE FROM users WHERE id = $1 RETURNING *';
    const values = [userIdToDelete];

    const result = await pool.query(query, values);

    res.status(200).json({ message: 'User deleted successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

//----Log Out------
app.get('/logOut', (req, res) => { 
  res.sendFile(__dirname + '/signIn.html'); 
});

// CRUD operations for managing books
// Create a new book
app.post('/api/books', authenticateUser, authorizeRole('moderator'), async (req, res) => {
  const { name, genre } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO books (name, genre) VALUES ($1, $2) RETURNING *',
      [name, genre]
    );
    res.status(201).json({ message: 'Book created successfully', book: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error creating book' });
  }
});

// Read all books
app.get('/api/books', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM books');
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error fetching books' });
  }
});

// Update a book
app.put('/api/books/:id', authenticateUser, authorizeRole('moderator'), async (req, res) => {
  const { id } = req.params;
  const { name, genre } = req.body;

  try {
    const result = await pool.query(
      'UPDATE books SET name = $1, genre = $2 WHERE id = $3 RETURNING *',
      [name, genre, id]
    );
    res.json({ message: 'Book updated successfully', book: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating book' });
  }
});

// Delete a book
app.delete('/api/books/:id', authenticateUser, authorizeRole('moderator'), async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM books WHERE id = $1 RETURNING *', [id]);
    res.json({ message: 'Book deleted successfully', book: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting book' });
  }
});

// Borrow a book
app.put('/api/borrow/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    // Check if the book exists and is available for borrowing
    const book = await pool.query('SELECT * FROM books WHERE id = $1 AND is_available = false', [id]);

    if (book.rows.length === 0) {
      // Book not found or already borrowed
      return res.status(404).json({ message: 'Book not available for borrowing' });
    }

    // Update the book status to indicate it's borrowed
    const borrowedBook = await pool.query(
      'UPDATE books SET is_available = true WHERE id = $1 RETURNING *',
      [id]
    );

    res.json({ message: 'Book borrowed successfully', book: borrowedBook.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error borrowing book' });
  }
});


app.listen(port, () => { 
  console.log(`Server is running on http://localhost:${port}`);
}); 