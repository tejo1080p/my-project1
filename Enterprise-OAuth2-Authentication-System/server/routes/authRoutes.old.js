const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { requireAuth } = require('../middleware/authMiddleware');
const {
  generateAccessToken,
  generateRefreshToken,
  setTokenCookies,
  clearTokenCookies,
  verifyRefreshToken
} = require('../utils/jwt');
const {
  generateState,
  generateCodeVerifier,
  generateCodeChallenge,
  getGoogleAuthUrl,
  getGoogleTokens,
  getGoogleUser,
  getFacebookAuthUrl,
  getFacebookTokens,
  getFacebookUser
} = require('../utils/oauth');

// In-memory store for OAuth state (use Redis in production)
const oauthStates = new Map();

/**
 * Manual signup with email/password
 */
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Create new user
    const user = new User({
      name,
      email,
      password,
      provider: 'local'
    });

    await user.save();

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    res.status(201).json({
      message: 'User created successfully',
      user: user.toJSON()
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

/**
 * Manual login with email/password
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if user registered with social login
    if (user.provider !== 'local') {
      return res.status(400).json({ 
        error: `This account is registered with ${user.provider}. Please use ${user.provider} login.` 
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    res.json({
      message: 'Login successful',
      user: user.toJSON()
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

/**
 * Google OAuth - Initiate
 */
router.get('/google', (req, res) => {
  try {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Store state and verifier (expires in 10 minutes)
    oauthStates.set(state, {
      codeVerifier,
      provider: 'google',
      timestamp: Date.now()
    });

    // Clean up old states (older than 10 minutes)
    for (const [key, value] of oauthStates.entries()) {
      if (Date.now() - value.timestamp > 10 * 60 * 1000) {
        oauthStates.delete(key);
      }
    }

    const authUrl = getGoogleAuthUrl(state, codeChallenge);
    res.redirect(authUrl);
  } catch (error) {
    console.error('Google OAuth init error:', error);
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_init_failed`);
  }
});

/**
 * Google OAuth - Callback
 */
router.get('/google/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=${error}`);
    }

    if (!code || !state) {
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=missing_params`);
    }

    // Verify state
    const storedData = oauthStates.get(state);
    if (!storedData || storedData.provider !== 'google') {
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=invalid_state`);
    }

    // Delete used state
    oauthStates.delete(state);

    // Exchange code for tokens
    const tokens = await getGoogleTokens(code, storedData.codeVerifier);
    
    // Get user info
    const googleUser = await getGoogleUser(tokens.access_token);

    // Find or create user
    let user = await User.findOne({ 
      $or: [
        { providerId: googleUser.id, provider: 'google' },
        { email: googleUser.email }
      ]
    });

    if (user) {
      // Update existing user
      if (user.provider !== 'google') {
        // Link Google account to existing local account
        user.provider = 'google';
        user.providerId = googleUser.id;
      }
      user.name = googleUser.name;
      user.avatar = googleUser.picture;
      user.lastLogin = new Date();
    } else {
      // Create new user
      user = new User({
        name: googleUser.name,
        email: googleUser.email,
        provider: 'google',
        providerId: googleUser.id,
        avatar: googleUser.picture,
        lastLogin: new Date()
      });
    }

    await user.save();

    // Generate JWT tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    // Redirect to dashboard
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/dashboard`);
  } catch (error) {
    console.error('Google callback error:', error);
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
  }
});

/**
 * Facebook OAuth - Initiate
 */
router.get('/facebook', (req, res) => {
  try {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Store state and verifier
    oauthStates.set(state, {
      codeVerifier,
      provider: 'facebook',
      timestamp: Date.now()
    });

    const authUrl = getFacebookAuthUrl(state, codeChallenge);
    res.redirect(authUrl);
  } catch (error) {
    console.error('Facebook OAuth init error:', error);
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_init_failed`);
  }
});

/**
 * Facebook OAuth - Callback
 */
router.get('/facebook/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=${error}`);
    }

    if (!code || !state) {
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=missing_params`);
    }

    // Verify state
    const storedData = oauthStates.get(state);
    if (!storedData || storedData.provider !== 'facebook') {
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=invalid_state`);
    }

    // Delete used state
    oauthStates.delete(state);

    // Exchange code for tokens
    const tokens = await getFacebookTokens(code, storedData.codeVerifier);
    
    // Get user info
    const facebookUser = await getFacebookUser(tokens.access_token);

    // Find or create user
    let user = await User.findOne({ 
      $or: [
        { providerId: facebookUser.id, provider: 'facebook' },
        { email: facebookUser.email }
      ]
    });

    if (user) {
      // Update existing user
      if (user.provider !== 'facebook') {
        user.provider = 'facebook';
        user.providerId = facebookUser.id;
      }
      user.name = facebookUser.name;
      user.avatar = facebookUser.picture?.data?.url || '';
      user.lastLogin = new Date();
    } else {
      // Create new user
      user = new User({
        name: facebookUser.name,
        email: facebookUser.email || `${facebookUser.id}@facebook.com`,
        provider: 'facebook',
        providerId: facebookUser.id,
        avatar: facebookUser.picture?.data?.url || '',
        lastLogin: new Date()
      });
    }

    await user.save();

    // Generate JWT tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    // Redirect to dashboard
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/dashboard`);
  } catch (error) {
    console.error('Facebook callback error:', error);
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
  }
});

/**
 * Get current user session
 */
router.get('/me', requireAuth, async (req, res) => {
  res.json({ user: req.user });
});

/**
 * Refresh access token
 */
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Find user
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Generate new access token
    const newAccessToken = generateAccessToken(user._id);

    // Set new access token cookie
    res.cookie('token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.json({ message: 'Token refreshed successfully' });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ error: 'Failed to refresh token' });
  }
});

/**
 * Logout
 */
router.post('/logout', requireAuth, async (req, res) => {
  try {
    // Clear refresh token from database
    req.user.refreshToken = null;
    await req.user.save();

    // Clear cookies
    clearTokenCookies(res);

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

/**
 * Facebook Data Deletion Callback
 * Required by Facebook Platform Policy
 * URL: https://yourdomain.com/auth/facebook/data-deletion
 */
router.post('/facebook/data-deletion', async (req, res) => {
  try {
    const { signed_request } = req.body;

    if (!signed_request) {
      return res.status(400).json({ 
        error: 'Missing signed_request parameter' 
      });
    }

    // Parse the signed request
    const [encodedSig, payload] = signed_request.split('.');
    
    // Decode the payload
    const data = JSON.parse(
      Buffer.from(payload, 'base64').toString('utf-8')
    );

    const userId = data.user_id;

    // Log the deletion request
    console.log(`Data deletion request received for Facebook user: ${userId}`);

    // Find and delete user by Facebook provider ID
    const user = await User.findOne({ 
      providerId: userId, 
      provider: 'facebook' 
    });

    if (user) {
      await User.deleteOne({ _id: user._id });
      console.log(`User deleted: ${user.email}`);
    }

    // Generate confirmation code
    const confirmationCode = `${userId}_${Date.now()}`;

    // Facebook expects this response format
    res.json({
      url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/data-deletion-status?confirmation=${confirmationCode}`,
      confirmation_code: confirmationCode
    });

  } catch (error) {
    console.error('Facebook data deletion error:', error);
    res.status(500).json({ 
      error: 'Failed to process data deletion request' 
    });
  }
});

/**
 * Data Deletion Status Page (GET endpoint for user-facing page)
 */
router.get('/data-deletion-status', (req, res) => {
  const { confirmation } = req.query;
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Data Deletion Request</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
          }
          .container {
            background: #f9fafb;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          }
          h1 { color: #1f2937; }
          p { color: #6b7280; line-height: 1.6; }
          .confirmation { 
            background: #e5e7eb; 
            padding: 10px; 
            border-radius: 6px; 
            margin: 20px 0;
            word-break: break-all;
          }
          .success { color: #10b981; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>✅ Data Deletion Request Received</h1>
          <p class="success">Your data deletion request has been processed successfully.</p>
          <p>All your personal data associated with this application has been permanently deleted from our systems.</p>
          ${confirmation ? `<div class="confirmation"><strong>Confirmation Code:</strong><br/>${confirmation}</div>` : ''}
          <p>If you have any questions, please contact support.</p>
        </div>
      </body>
    </html>
  `);
});

module.exports = router;

