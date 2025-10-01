const express = require('express');
const router = express.Router();
const productController = require('../controllers/productController');

// Get all products
router.get('/', productController.getAllProducts);

// Create a new product
router.post('/', productController.createProduct);

// Get products by category
router.get('/category/:category', productController.getProductsByCategory);

// Get products by color
router.get('/by-color/:color', productController.getProductsByColor);

// Delete a product
router.delete('/:id', productController.deleteProduct);

module.exports = router;
