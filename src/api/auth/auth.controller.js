const pool = require('../../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Get current authenticated user
const authMe = async (req, res) => {
  try {
    // req.user.userId comes from JWT middleware
    const result = await pool.query(
      "SELECT id, name, email, role, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      console.log("User not found");
      return res.status(404).json({ error: "User not found" });
    } 
    
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.log("ERROR: ", error);
    res.status(500).json({ error: "Server error" });
  }
}

// User registration
const register = async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, email, hashedPassword, role]
    );

    res.status(201).json({ message: 'User registered successfully', user: newUser.rows[0] });
  } catch (error) {
    // console.log("ERROR: ", error);
    if (error.code === '23505') { // Unique constraint violation
      return res.status(409).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Server error' });
  }
};

// User login
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }else {
      // Update database to update last seen
      try{
        const update_last_seen = await pool.query(
          "UPDATE users SET last_seen = NOW() WHERE email = $1",
          [email]
        );
      } catch (error) {
        console.error("LAST SEEN ERROR: ", error);
      }

    }

    const validPassword = await bcrypt.compare(password, user.rows[0].password);

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.rows[0].id, role: user.rows[0].role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    res.status(200).json({ token, user: user.rows[0] });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  authMe,
  register,
  login,
};
