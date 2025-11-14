const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';

// Access token expires in 15 minutes
const ACCESS_TOKEN_EXPIRY = '15m';
// Refresh token expires in 7 days
const REFRESH_TOKEN_EXPIRY = '7d';

/**
 * Generate access token
 */
const generateAccessToken = (userId, role = 'user') => {
  return jwt.sign(
    { userId, role, type: 'access' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
};

/**
 * Generate refresh token
 */
const generateRefreshToken = (userId) => {
  return jwt.sign(
    { userId, type: 'refresh' },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
};

/**
 * Verify access token
 */
const verifyAccessToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }
    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

/**
 * Verify refresh token
 */
const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET);
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }
    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

/**
 * Set token cookies in response change:::
 */
const setTokenCookies = (res, accessToken, refreshToken) => {
  const isProduction = process.env.NODE_ENV === 'production';

  const baseOptions = {
    httpOnly: true,
    secure: isProduction,                            // only true on Render
    sameSite: isProduction ? 'none' : 'lax',         // ✅ allow cross-site cookies in prod
  };

  // Access token cookie (15 minutes)
  res.cookie('token', accessToken, {
    ...baseOptions,
    maxAge: 15 * 60 * 1000,                          // 15 minutes
  });

  // Refresh token cookie (7 days)
  res.cookie('refreshToken', refreshToken, {
    ...baseOptions,
    maxAge: 7 * 24 * 60 * 60 * 1000,                 // 7 days
  });
};

const clearTokenCookies = (res) => {
  const isProduction = process.env.NODE_ENV === 'production';

  const baseOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
  };

  res.clearCookie('token', baseOptions);
  res.clearCookie('refreshToken', baseOptions);
};


module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  setTokenCookies,
  clearTokenCookies
};

