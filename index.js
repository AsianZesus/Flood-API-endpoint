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

// endpoint for user registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {

    // query the database to see if a user with the given email already exists
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length > 0) {
      // if a user with the given email already exists, return an error response
      return res.status(409).json({ error: 'User already exists.' });
    }

    // insert the new user into the database
    const query = 'INSERT INTO users (email, password) VALUES ($1, $2)';
    await pool.query(query, [email, password]);

    // return a success response
    return res.status(200).json({ message: 'User registered successfully.' });

  } catch (error) {
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