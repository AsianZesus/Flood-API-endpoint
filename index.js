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
  if (!authHeader) {
    // if no Authorization header is present, return an error response
    return res.status(401).json({ error: 'Authorization header missing.' });
  }

  const token = authHeader.split(' ')[1];
  const secretKey = process.env.JWT_SECRET_KEY;
  try {
    // verify the JWT and extract the payload
    const payload = jwt.verify(token, secretKey);
    req.user = payload;
    next();
  } catch (error) {
    // if the JWT is invalid or expired, return an error response
    console.error(error);
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// example protected endpoint that requires authentication
app.get('/protected', authenticate, (req, res) => {
  // access the user's ID from the JWT payload
  const userId = req.user.userId;
  // query the database or perform any other logic based on the user's ID
  // return a response with the results of the query or other logic
});


// enpoint for user registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    // query the database to see if a user with the given email already exists
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length > 0) {
      // if a user with the given email already exists, return an error response
      return res.status(409).json({ error: 'User already exists.' });
    }

    // hash and salt the passworda
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // insert the new user into the database with the hashed password
    const query = 'INSERT INTO users (email, password) VALUES ($1, $2)';
    await pool.query(query, [email, hashedPassword]);

    // return a success response
    return res.status(200).json({ message: 'User registered successfully.' });

  } catch (error) {
    // log the error and return an error response
    console.error(error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// endpoint for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    // query the database to get the user with the given email
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      // if no user with the given email exists, return an error response
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // compare the given password with the stored hashed password
    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // if the given password doesn't match the stored hashed password, return an error response
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // generate a JWT with the user's ID and any other necessary information
    const payload = { userId: user.id };
    const secretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(payload, secretKey);

    // return a success response with the JWT
    return res.status(200).json({ token });

  } catch (error) {
    // log the error and return an error response
    console.error(error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});



app.listen(port, () => {
  console.log(`Server is running on port ${port}.`);
});