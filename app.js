// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');


const port = process.env.PORT || 3000;

// create a connection pool to the PostgreSQL database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// middleware for parsing JSON in request body
app.use(bodyParser.json());

// enable CORS
app.use(cors());

// set security-related HTTP headers
app.use(helmet());

// limit the rate of requests from a single IP address
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// middleware function for verifying JWT and extracting payload
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    // extract the JWT from the Authorization header
    const token = authHeader.split(' ')[1];
    try {
      // verify the JWT and extract the payload
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
}

// API endpoint for registering a new user
app.post('/register', async (req, res) => {
  try {
    const {email, password } = req.body;
    // hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // insert the new user into the "users" table
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );

    // create a JWT for the new user
    const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.status(201).json({ user: result.rows[0], token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint for logging in a user
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // get the user with the specified email address
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    // compare the password hash to the provided password
    const match = await bcrypt.compare(password, result.rows[0].password);

    if (!match) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    // create a JWT for the authenticated user
    const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.status(200).json({ user: result.rows[0], token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint for getting the current user
app.get('/me', authenticate, async (req, res) => {
  try {
    const { id } = req.user;
    // get the user with the specified ID
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);

    res.status(200).json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = \$1', [email]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Configure the email transporter
    const transporter = nodemailer.createTransport({
      service: 'gmail', // or another email service
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Set up the password reset email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset',
      text: `Please use the following token to reset your password: \${token}`
    };

    // Send the password reset email
    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const { id } = decoded;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = \$1 WHERE id = \$2', [hashedPassword, id]);

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});