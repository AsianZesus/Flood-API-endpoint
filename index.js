// Load environment variables from .env file
require('dotenv').config(); 

const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
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

// endpoint for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // query the database for the user with the given email
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (rows.length === 0) {
      // if no user is found, return an error response
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // compare the provided password with the password stored in the database
    const storedPassword = rows[0].password.toString();

    if (password !== storedPassword) {
      // if the passwords don't match, return an error response
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // if the passwords match, return a success response
    return res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    if (error.code === '23505') {
      // if the error is a unique constraint violation, return an error response
      return res.status(409).json({ error: 'User already exists.' });
    }

    // log the error and return an error response
    console.error(error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// handle 404 errors
app.use((req, res, next) => {
  res.status(404).json({ error: 'Endpoint not found' });
  console.log(req);
  next();
});

// handle all other errors
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Internal server error.' });
});

// start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});