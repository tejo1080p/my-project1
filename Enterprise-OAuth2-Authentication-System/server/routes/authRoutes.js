const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { requireAuth } = require('../middleware/authMiddleware');
const { requireActive } = require('../middleware/rbac');
const { validateSignup, validateLogin } = require('../middleware/validation');
const { authRateLimit, oauthRateLimit, signupRateLimit } = require('../middleware/rateLimit');
const { logger } = require('../utils/logger');
const { tokenBlacklist } = require('../utils/tokenBlacklist');
const {
  generateAccessToken,
  generateRefreshToken,
  setTokenCookies,
  clearTokenCookies,
  verifyRefreshToken
} = require('../utils/jwt');
const {
  generateState,
  generateNonce,
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

// Clean up old OAuth states periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of oauthStates.entries()) {
    if (now - value.timestamp > 10 * 60 * 1000) { // 10 minutes
      oauthStates.delete(key);
    }
  }
}, 60 * 1000); // Run every minute

/**
 * Manual signup with email/password
 */
router.post('/signup', signupRateLimit, validateSignup, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.logAuth('signup', false, {
        correlationId: req.correlationId,
        email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'email_exists' }
      });

      return res.status(400).json({ 
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }

    // Create new user with default role
    const user = new User({
      name,
      email,
      password,
      provider: 'local',
      role: 'user',
      isActive: true,
      isEmailVerified: false,
      loginCount: 0
    });

    // Add audit log
    user.addAuditLog('account_created', { 
      provider: 'local',
      method: 'email_password' 
    }, req);

    await user.save();

    // Generate tokens
    const accessToken = generateAccessToken(user._id, user.role);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    user.lastLogin = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount += 1;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    logger.logAuth('signup', true, {
      correlationId: req.correlationId,
      userId: user._id,
      email,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.status(201).json({
      message: 'User created successfully',
      user: user.toJSON()
    });
  } catch (error) {
    logger.error('Signup failed', error, {
      correlationId: req.correlationId,
      email: req.body?.email,
      action: 'signup'
    });

    res.status(500).json({ error: 'Failed to create user' });
  }
});

/**
 * Manual login with email/password
 */
router.post('/login', authRateLimit, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      logger.logAuth('login', false, {
        correlationId: req.correlationId,
        email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'user_not_found' }
      });

      return res.status(401).json({ 
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      logger.logAuth('login', false, {
        correlationId: req.correlationId,
        userId: user._id,
        email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'account_inactive' }
      });

      return res.status(403).json({ 
        error: 'Account is inactive. Please contact support.',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Check if user has password (OAuth-only accounts)
    if (!user.password) {
      logger.logAuth('login', false, {
        correlationId: req.correlationId,
        userId: user._id,
        email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'oauth_account', provider: user.provider }
      });

      return res.status(400).json({ 
        error: `This account is registered with ${user.provider}. Please use ${user.provider} login.`,
        code: 'OAUTH_ACCOUNT'
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      logger.logAuth('login', false, {
        correlationId: req.correlationId,
        userId: user._id,
        email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'invalid_password' }
      });

      return res.status(401).json({ 
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount += 1;

    // Add audit log
    user.addAuditLog('login_success', { 
      method: 'email_password' 
    }, req);

    // Generate tokens
    const accessToken = generateAccessToken(user._id, user.role);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    logger.logAuth('login', true, {
      correlationId: req.correlationId,
      userId: user._id,
      email,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({
      message: 'Login successful',
      user: user.toJSON()
    });
  } catch (error) {
    logger.error('Login failed', error, {
      correlationId: req.correlationId,
      email: req.body?.email,
      action: 'login'
    });

    res.status(500).json({ error: 'Failed to login' });
  }
});

/**
 * Google OAuth - Initiate
 */
router.get('/google', oauthRateLimit, (req, res) => {
  try {
    const state = generateState();
    const nonce = generateNonce();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const returnTo = req.query.returnTo || '/dashboard';

    // Store state and verifier (expires in 10 minutes)
    oauthStates.set(state, {
      codeVerifier,
      nonce,
      provider: 'google',
      returnTo,
      timestamp: Date.now()
    });

    logger.info('OAuth flow initiated', {
      correlationId: req.correlationId,
      provider: 'google',
      action: 'oauth_init',
      ip: req.ip
    });

    const authUrl = getGoogleAuthUrl(state, codeChallenge, nonce);
    res.redirect(authUrl);
  } catch (error) {
    logger.error('OAuth initiation failed', error, {
      correlationId: req.correlationId,
      provider: 'google',
      action: 'oauth_init'
    });

    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_init_failed`);
  }
});

/**
 * Google OAuth - Callback
 */
router.get('/google/callback', async (req, res) => {
  try {
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      logger.logAuth('oauth_google', false, {
        correlationId: req.correlationId,
        provider: 'google',
        ip: req.ip,
        details: { error: oauthError }
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=${oauthError}`);
    }

    if (!code || !state) {
      logger.logAuth('oauth_google', false, {
        correlationId: req.correlationId,
        provider: 'google',
        ip: req.ip,
        details: { reason: 'missing_params' }
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=missing_params`);
    }

    // Verify state
    const storedData = oauthStates.get(state);
    if (!storedData || storedData.provider !== 'google') {
      logger.logSecurity('oauth_invalid_state', 'warn', {
        correlationId: req.correlationId,
        provider: 'google',
        ip: req.ip,
        details: { reason: 'invalid_state' }
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=invalid_state`);
    }

    // Delete used state (prevent replay)
    oauthStates.delete(state);
    const returnTo = storedData.returnTo || '/dashboard';

    // Exchange code for tokens
    const tokens = await getGoogleTokens(code, storedData.codeVerifier);
    
    // Get user info
    const googleUser = await getGoogleUser(tokens.access_token);
    
    // Log avatar URL for debugging
    console.log('Google user data:', {
      id: googleUser.id,
      email: googleUser.email,
      name: googleUser.name,
      picture: googleUser.picture
    });

    // Check for nonce replay attack
    let user = await User.findOne({ email: googleUser.email });
    
    if (user && user.isNonceUsed(storedData.nonce)) {
      logger.logSecurity('nonce_replay_detected', 'error', {
        correlationId: req.correlationId,
        userId: user._id,
        provider: 'google',
        ip: req.ip
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=security_error`);
    }

    // Find or create user
    if (!user) {
      // Check if provider ID exists with different email
      const existingByProviderId = await User.findOne({ 
        providerId: googleUser.id, 
        provider: 'google' 
      });

      if (existingByProviderId) {
        user = existingByProviderId;
      } else {
        // Create new user
        user = new User({
          name: googleUser.name,
          email: googleUser.email,
          provider: 'google',
          providerId: googleUser.id,
          avatar: googleUser.picture,
          role: 'user',
          isActive: true,
          isEmailVerified: true, // OAuth emails are pre-verified
          loginCount: 0
        });

        // Link provider
        user.linkProvider('google', googleUser.id, googleUser.email, googleUser.picture);

        user.addAuditLog('account_created', { 
          provider: 'google',
          email: googleUser.email 
        }, req);
      }
    } else {
      // Check if account is active
      if (!user.isActive) {
        logger.logAuth('oauth_google', false, {
          correlationId: req.correlationId,
          userId: user._id,
          provider: 'google',
          ip: req.ip,
          details: { reason: 'account_inactive' }
        });

        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=account_inactive`);
      }

      // Initialize consents if not present
      if (!user.consents) {
        user.consents = {
          profileSync: true,
          dataProcessing: true,
          marketing: false
        };
      }

      // Update user info if consent given or if avatar is missing
      const shouldSync = user.consents.profileSync !== false || !user.avatar;
      if (shouldSync) {
        user.name = googleUser.name;
        if (googleUser.picture) {
          user.avatar = googleUser.picture;
        }
      }

      // Ensure provider is linked
      if (!user.hasLinkedProvider('google')) {
        user.linkProvider('google', googleUser.id, googleUser.email, googleUser.picture);
      }

      // Update primary provider if needed
      if (user.provider !== 'google') {
        user.provider = 'google';
        user.providerId = googleUser.id;
      }

      user.addAuditLog('login_success', { 
        provider: 'google',
        email: googleUser.email 
      }, req);
    }

    // Mark nonce as used
    user.markNonceAsUsed(storedData.nonce);

    // Update last login
    user.lastLogin = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount += 1;

    // Generate JWT tokens
    const accessToken = generateAccessToken(user._id, user.role);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    logger.logAuth('oauth_google', true, {
      correlationId: req.correlationId,
      userId: user._id,
      provider: 'google',
      ip: req.ip,
      email: googleUser.email
    });

    // Redirect to original destination
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}${returnTo}`);
  } catch (error) {
    logger.error('OAuth callback failed', error, {
      correlationId: req.correlationId,
      provider: 'google',
      action: 'oauth_callback'
    });

    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
  }
});

/**
 * Facebook OAuth - Initiate
 */
router.get('/facebook', oauthRateLimit, (req, res) => {
  try {
    const state = generateState();
    const nonce = generateNonce();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const returnTo = req.query.returnTo || '/dashboard';

    // Store state and verifier
    oauthStates.set(state, {
      codeVerifier,
      nonce,
      provider: 'facebook',
      returnTo,
      timestamp: Date.now()
    });

    logger.info('OAuth flow initiated', {
      correlationId: req.correlationId,
      provider: 'facebook',
      action: 'oauth_init',
      ip: req.ip
    });

    const authUrl = getFacebookAuthUrl(state, codeChallenge, nonce);
    res.redirect(authUrl);
  } catch (error) {
    logger.error('OAuth initiation failed', error, {
      correlationId: req.correlationId,
      provider: 'facebook',
      action: 'oauth_init'
    });

    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_init_failed`);
  }
});

/**
 * Facebook OAuth - Callback
 */
router.get('/facebook/callback', async (req, res) => {
  try {
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      logger.logAuth('oauth_facebook', false, {
        correlationId: req.correlationId,
        provider: 'facebook',
        ip: req.ip,
        details: { error: oauthError }
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=${oauthError}`);
    }

    if (!code || !state) {
      logger.logAuth('oauth_facebook', false, {
        correlationId: req.correlationId,
        provider: 'facebook',
        ip: req.ip,
        details: { reason: 'missing_params' }
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=missing_params`);
    }

    // Verify state
    const storedData = oauthStates.get(state);
    if (!storedData || storedData.provider !== 'facebook') {
      logger.logSecurity('oauth_invalid_state', 'warn', {
        correlationId: req.correlationId,
        provider: 'facebook',
        ip: req.ip,
        details: { reason: 'invalid_state' }
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=invalid_state`);
    }

    // Delete used state (prevent replay)
    oauthStates.delete(state);
    const returnTo = storedData.returnTo || '/dashboard';

    // Exchange code for tokens
    const tokens = await getFacebookTokens(code, storedData.codeVerifier);
    
    // Get user info
    const facebookUser = await getFacebookUser(tokens.access_token);
    const email = facebookUser.email || `${facebookUser.id}@facebook.com`;
    
    // Log avatar URL for debugging
    console.log('Facebook user data:', {
      id: facebookUser.id,
      email: facebookUser.email,
      name: facebookUser.name,
      picture: facebookUser.picture
    });

    // Check for nonce replay attack
    let user = await User.findOne({ email });
    
    if (user && user.isNonceUsed(storedData.nonce)) {
      logger.logSecurity('nonce_replay_detected', 'error', {
        correlationId: req.correlationId,
        userId: user._id,
        provider: 'facebook',
        ip: req.ip
      });

      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=security_error`);
    }

    // Find or create user
    if (!user) {
      // Check if provider ID exists with different email
      const existingByProviderId = await User.findOne({ 
        providerId: facebookUser.id, 
        provider: 'facebook' 
      });

      if (existingByProviderId) {
        user = existingByProviderId;
      } else {
        // Create new user
        user = new User({
          name: facebookUser.name,
          email,
          provider: 'facebook',
          providerId: facebookUser.id,
          avatar: facebookUser.picture?.data?.url || '',
          role: 'user',
          isActive: true,
          isEmailVerified: !!facebookUser.email,
          loginCount: 0
        });

        // Link provider
        user.linkProvider('facebook', facebookUser.id, email, facebookUser.picture?.data?.url);

        user.addAuditLog('account_created', { 
          provider: 'facebook',
          email 
        }, req);
      }
    } else {
      // Check if account is active
      if (!user.isActive) {
        logger.logAuth('oauth_facebook', false, {
          correlationId: req.correlationId,
          userId: user._id,
          provider: 'facebook',
          ip: req.ip,
          details: { reason: 'account_inactive' }
        });

        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=account_inactive`);
      }

      // Initialize consents if not present
      if (!user.consents) {
        user.consents = {
          profileSync: true,
          dataProcessing: true,
          marketing: false
        };
      }

      // Update user info if consent given or if avatar is missing
      const shouldSync = user.consents.profileSync !== false || !user.avatar;
      if (shouldSync) {
        user.name = facebookUser.name;
        const fbAvatar = facebookUser.picture?.data?.url;
        if (fbAvatar) {
          user.avatar = fbAvatar;
        }
      }

      // Ensure provider is linked
      if (!user.hasLinkedProvider('facebook')) {
        user.linkProvider('facebook', facebookUser.id, email, facebookUser.picture?.data?.url);
      }

      // Update primary provider if needed
      if (user.provider !== 'facebook') {
        user.provider = 'facebook';
        user.providerId = facebookUser.id;
      }

      user.addAuditLog('login_success', { 
        provider: 'facebook',
        email 
      }, req);
    }

    // Mark nonce as used
    user.markNonceAsUsed(storedData.nonce);

    // Update last login
    user.lastLogin = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount += 1;

    // Generate JWT tokens
    const accessToken = generateAccessToken(user._id, user.role);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    logger.logAuth('oauth_facebook', true, {
      correlationId: req.correlationId,
      userId: user._id,
      provider: 'facebook',
      ip: req.ip,
      email
    });

    // Redirect to original destination
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}${returnTo}`);
  } catch (error) {
    logger.error('OAuth callback failed', error, {
      correlationId: req.correlationId,
      provider: 'facebook',
      action: 'oauth_callback'
    });

    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
  }
});

/**
 * Get current user session
 */
router.get('/me', requireAuth, requireActive, (req, res) => {
  res.json({ 
    user: req.user,
    permissions: {
      role: req.user.role,
      claims: req.user.claims,
      isAdmin: req.user.role === 'admin',
      isModerator: req.user.role === 'moderator' || req.user.role === 'admin'
    }
  });
});

/**
 * Refresh access token
 */
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ 
        error: 'Refresh token required',
        code: 'REFRESH_TOKEN_REQUIRED'
      });
    }

    // Check if token is blacklisted
    if (tokenBlacklist.isBlacklisted(refreshToken)) {
      logger.logSecurity('blacklisted_token_used', 'warn', {
        correlationId: req.correlationId,
        ip: req.ip,
        action: 'token_refresh'
      });

      return res.status(401).json({ 
        error: 'Token has been revoked',
        code: 'TOKEN_REVOKED'
      });
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Find user
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      logger.logSecurity('invalid_refresh_token', 'warn', {
        correlationId: req.correlationId,
        userId: decoded.userId,
        ip: req.ip,
        action: 'token_refresh'
      });

      return res.status(401).json({ 
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({ 
        error: 'Account is inactive',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Generate new access token
    const newAccessToken = generateAccessToken(user._id, user.role);

    // Set new access token cookie
    res.cookie('token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    logger.info('Token refreshed', {
      correlationId: req.correlationId,
      userId: user._id,
      action: 'token_refresh'
    });

    res.json({ message: 'Token refreshed successfully' });
  } catch (error) {
    logger.error('Token refresh failed', error, {
      correlationId: req.correlationId,
      action: 'token_refresh'
    });

    res.status(401).json({ 
      error: 'Failed to refresh token',
      code: 'REFRESH_FAILED'
    });
  }
});

/**
 * Logout
 */
router.post('/logout', requireAuth, async (req, res) => {
  try {
    const user = req.user;

    // Blacklist current tokens
    const accessToken = req.cookies.token;
    const refreshToken = req.cookies.refreshToken;

    if (accessToken) {
      tokenBlacklist.add(accessToken, Date.now() + 15 * 60 * 1000); // 15 minutes
    }
    if (refreshToken) {
      tokenBlacklist.add(refreshToken, Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    }

    // Clear refresh token from database
    user.refreshToken = null;

    // Add audit log
    user.addAuditLog('logout', {}, req);
    
    await user.save();

    // Clear cookies
    clearTokenCookies(res);

    logger.logAuth('logout', true, {
      correlationId: req.correlationId,
      userId: user._id,
      ip: req.ip
    });

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout failed', error, {
      correlationId: req.correlationId,
      userId: req.user?._id,
      action: 'logout'
    });

    res.status(500).json({ error: 'Failed to logout' });
  }
});

/**
 * Logout from all devices
 */
router.post('/logout-all', requireAuth, async (req, res) => {
  try {
    const user = req.user;

    // Blacklist current refresh token
    if (user.refreshToken) {
      tokenBlacklist.add(user.refreshToken, Date.now() + 7 * 24 * 60 * 60 * 1000);
    }

    // Clear refresh token from database
    user.refreshToken = null;

    // Add audit log
    user.addAuditLog('logout_all_devices', {}, req);

    await user.save();

    // Clear cookies
    clearTokenCookies(res);

    logger.logAuth('logout_all', true, {
      correlationId: req.correlationId,
      userId: user._id,
      ip: req.ip
    });

    res.json({ message: 'Logged out from all devices successfully' });
  } catch (error) {
    logger.error('Logout all failed', error, {
      correlationId: req.correlationId,
      userId: req.user?._id,
      action: 'logout_all'
    });

    res.status(500).json({ error: 'Failed to logout from all devices' });
  }
});

/**
 * Facebook Data Deletion Callback (Required by Facebook)
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
    const data = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));
    const userId = data.user_id;

    logger.info('Facebook data deletion requested', {
      correlationId: req.correlationId,
      facebookUserId: userId,
      action: 'facebook_data_deletion'
    });

    // Find and delete user by Facebook provider ID
    const user = await User.findOne({ 
      providerId: userId, 
      provider: 'facebook' 
    });

    if (user) {
      await User.deleteOne({ _id: user._id });
      
      logger.logAuth('facebook_data_deletion', true, {
        correlationId: req.correlationId,
        userId: user._id,
        email: user.email,
        facebookUserId: userId
      });
    }

    // Generate confirmation code
    const confirmationCode = `${userId}_${Date.now()}`;

    res.json({
      url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/data-deletion-status?confirmation=${confirmationCode}`,
      confirmation_code: confirmationCode
    });
  } catch (error) {
    logger.error('Facebook data deletion failed', error, {
      correlationId: req.correlationId,
      action: 'facebook_data_deletion'
    });

    res.status(500).json({ 
      error: 'Failed to process data deletion request' 
    });
  }
});

/**
 * Data Deletion Status Page
 */
router.get('/data-deletion-status', (req, res) => {
  const { confirmation } = req.query;
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Data Deletion Request</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
            background: #f5f5f5;
          }
          .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          }
          h1 { color: #1f2937; margin-bottom: 20px; }
          p { color: #6b7280; line-height: 1.6; margin: 15px 0; }
          .confirmation { 
            background: #e5e7eb; 
            padding: 15px; 
            border-radius: 6px; 
            margin: 20px 0;
            word-break: break-all;
            font-family: monospace;
          }
          .success { color: #10b981; font-weight: 600; font-size: 18px; }
          .icon { font-size: 48px; margin-bottom: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon">✅</div>
          <h1>Data Deletion Request Received</h1>
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

