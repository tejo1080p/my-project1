const crypto = require('crypto');

/**
 * CSRF Protection for OAuth flows and cookie-based authentication
 * 
 * This middleware generates and validates CSRF tokens to prevent
 * Cross-Site Request Forgery attacks
 */

// In-memory CSRF token store (use Redis in production for distributed systems)
const csrfTokens = new Map();

// Clean up old tokens every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of csrfTokens.entries()) {
    if (now > data.expiresAt) {
      csrfTokens.delete(token);
    }
  }
}, 60 * 60 * 1000);

/**
 * Generate CSRF token
 */
const generateCsrfToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Store CSRF token
 */
const storeCsrfToken = (token, sessionId, expiryMinutes = 60) => {
  csrfTokens.set(token, {
    sessionId,
    createdAt: Date.now(),
    expiresAt: Date.now() + expiryMinutes * 60 * 1000
  });
};

/**
 * Verify CSRF token
 */
const verifyCsrfToken = (token, sessionId) => {
  const data = csrfTokens.get(token);
  
  if (!data) return false;
  
  // Check if expired
  if (Date.now() > data.expiresAt) {
    csrfTokens.delete(token);
    return false;
  }
  
  // Verify session match
  if (data.sessionId !== sessionId) {
    return false;
  }
  
  return true;
};

/**
 * Delete CSRF token after use (single-use tokens)
 */
const deleteCsrfToken = (token) => {
  csrfTokens.delete(token);
};

/**
 * Middleware to add CSRF token to response
 * Use on routes that render forms or initiate state-changing operations
 */
const addCsrfToken = (req, res, next) => {
  // Generate session ID from user ID or create temporary one
  const sessionId = req.user?.id || req.sessionId || crypto.randomUUID();
  req.sessionId = sessionId;
  
  // Generate CSRF token
  const csrfToken = generateCsrfToken();
  storeCsrfToken(csrfToken, sessionId);
  
  // Add to response
  res.locals.csrfToken = csrfToken;
  res.setHeader('X-CSRF-Token', csrfToken);
  
  next();
};

/**
 * Middleware to verify CSRF token
 * Use on state-changing routes (POST, PUT, DELETE)
 */
const verifyCsrf = (req, res, next) => {
  // Skip verification for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Get token from header or body
  const token = req.headers['x-csrf-token'] || 
                req.body?.csrfToken || 
                req.query?.csrfToken;
  
  if (!token) {
    return res.status(403).json({ 
      error: 'CSRF token missing',
      code: 'CSRF_TOKEN_MISSING'
    });
  }
  
  // Get session ID
  const sessionId = req.user?.id || req.sessionId || req.headers['x-session-id'];
  
  if (!sessionId) {
    return res.status(403).json({ 
      error: 'Session ID missing',
      code: 'SESSION_ID_MISSING'
    });
  }
  
  // Verify token
  if (!verifyCsrfToken(token, sessionId)) {
    return res.status(403).json({ 
      error: 'Invalid CSRF token',
      code: 'CSRF_TOKEN_INVALID'
    });
  }
  
  // Delete token after use (one-time use)
  deleteCsrfToken(token);
  
  next();
};

/**
 * Generate CSRF token for OAuth state parameter
 * This is used in addition to the state parameter for extra security
 */
const generateOAuthCsrf = (userId, provider) => {
  const token = generateCsrfToken();
  const key = `oauth:${userId}:${provider}`;
  
  storeCsrfToken(token, key, 15); // 15 minutes for OAuth flow
  
  return token;
};

/**
 * Verify CSRF token for OAuth callback
 */
const verifyOAuthCsrf = (token, userId, provider) => {
  const key = `oauth:${userId}:${provider}`;
  const valid = verifyCsrfToken(token, key);
  
  if (valid) {
    deleteCsrfToken(token);
  }
  
  return valid;
};

module.exports = {
  addCsrfToken,
  verifyCsrf,
  generateCsrfToken,
  storeCsrfToken,
  verifyCsrfToken,
  deleteCsrfToken,
  generateOAuthCsrf,
  verifyOAuthCsrf
};

