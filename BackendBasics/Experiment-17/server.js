import express from 'express';
const app = express();
const PORT = process.env.PORT || 3000;

// Logging middleware: method, url, timestamp
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  next();
});

// Bearer token auth middleware
function requireBearerToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const [scheme, token] = auth.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Authorization header missing or incorrect' });
  }
  if (token !== 'mysecrettoken') {
    return res.status(403).json({ message: 'Invalid token' });
  }
  next();
}

// Public route
app.get('/public', (req, res) => {
  res.status(200).send('This is a public route. No authentication required.');
});

// Root route - guide users
app.get('/', (req, res) => {
  res.status(200).send('Server is running. Try GET /public or GET /protected with Authorization: Bearer mysecrettoken');
});

// Protected route
app.get('/protected', requireBearerToken, (req, res) => {
  res.status(200).send('You have accessed a protected route with a valid Bearer token!');
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});