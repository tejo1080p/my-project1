// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const productRoutes = require('./routes/productRoutes');

const app = express();

// 🔹 Middleware
app.use(express.json()); // parse JSON request body
app.use(cors());

// 🔹 Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/ecommerce')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error(err));

// 🔹 Routes

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to E-commerce Catalog API');
});

// Product routes

app.use('/products', productRoutes);

//  Start server
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
