// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const Product = require('./models/Product');

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

// GET all products
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET products by category
app.get('/products/category/:cat', async (req, res) => {
  try {
    const products = await Product.find({ category: req.params.cat });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET only variant color & size
app.get('/products/variants/all', async (req, res) => {
  try {
    const products = await Product.find({}, { "variants.color": 1, "variants.size": 1, _id: 0 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST a new product
app.post('/products', async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 🔹 Start server
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
