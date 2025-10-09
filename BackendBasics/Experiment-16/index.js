const express = require('express');
const app = express();
const port = 3000;

// Middleware to log requests with date & time
app.use((req, res, next) => {
  const now = new Date().toLocaleString();
  console.log(`[${now}] ${req.method} ${req.url}`);
  next();
});

// Middleware to parse JSON bodies
app.use(express.json());

let users = [];

// ------------------------
// Public User Routes
// ------------------------

// Create a user (POST /users)
app.post('/users', (req, res) => {
  const user = req.body;
  users.push(user);
  res.status(201).json({ message: 'User added', user });
});

// Get all users (GET /users)
app.get('/users', (req, res) => {
  res.status(200).json(users);
});

// Update a user (PUT /users/:id)
app.put('/users/:id', (req, res) => {
  const id = req.params.id;
  const updatedUser = req.body;
  users = users.map(user => (user.id === id ? updatedUser : user));
  res.status(200).json({ message: 'User updated', updatedUser });
});

// Delete a user (DELETE /users/:id)
app.delete('/users/:id', (req, res) => {
  const id = req.params.id;
  users = users.filter(user => user.id !== id);
  res.status(200).json({ message: 'User deleted' });
});

// ------------------------
// Auth Middleware
// ------------------------
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']; // get token from headers
  if (token === 'mysecrettoken') {
    next(); // valid token → continue
  } else {
    res.status(403).json({ message: 'Forbidden' }); // invalid → block
  }
}

// ------------------------
// Admin Router
// ------------------------
const router = express.Router();

// Apply authMiddleware to all admin routes
router.use(authMiddleware);

// Admin router middleware for logging
router.use((req, res, next) => {
  const now = new Date().toLocaleString();
  console.log(`[${now}] Admin router middleware executed`);
  next();
});

// Admin dashboard route
router.get('/dashboard', (req, res) => {
  res.send('Admin dashboard');
});

app.use('/admin', router);

// ------------------------
// Error-handling middleware
// ------------------------
app.use((err, req, res, next) => {
  const now = new Date().toLocaleString();
  console.error(`[${now}] Error stack:`, err.stack);
  res.status(500).send('Something went wrong!');
});

// ------------------------
// Start server
// ------------------------
app.listen(port, () => {
  console.log(`✅ Server running on http://localhost:${port}`);
});
