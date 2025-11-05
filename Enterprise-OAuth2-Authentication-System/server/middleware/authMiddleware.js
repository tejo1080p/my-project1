const { verifyAccessToken } = require('../utils/jwt');
const User = require('../models/User');

/**
 * Middleware to protect routes - requires valid JWT
 */
const requireAuth = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Verify token
    const decoded = verifyAccessToken(token);
    
    // Get user from database
    const user = await User.findById(decoded.userId).select('-password -refreshToken');
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

/**
 * Optional auth - attaches user if token exists, but doesn't require it
 */
const optionalAuth = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    
    if (token) {
      const decoded = verifyAccessToken(token);
      const user = await User.findById(decoded.userId).select('-password -refreshToken');
      if (user) {
        req.user = user;
      }
    }
  } catch (error) {
    // Ignore errors for optional auth
  }
  next();
};

module.exports = {
  requireAuth,
  optionalAuth
};

