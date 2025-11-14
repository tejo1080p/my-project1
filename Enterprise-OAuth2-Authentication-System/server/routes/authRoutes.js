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
} = require('../utils/oauth');

const { config } = require('../config/environment');

// In-memory store for OAuth state
const oauthStates = new Map();

// Cleanup old states
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of oauthStates.entries()) {
    if (now - value.timestamp > 10 * 60 * 1000) oauthStates.delete(key);
  }
}, 60 * 1000);


/* ----------------------------
 * GOOGLE OAUTH - START
 * ---------------------------- */
router.get('/google', oauthRateLimit, (req, res) => {
  try {
    const state = generateState();
    const nonce = generateNonce();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const returnTo = req.query.returnTo || '/dashboard';

    oauthStates.set(state, {
      codeVerifier,
      nonce,
      provider: 'google',
      returnTo,
      timestamp: Date.now()
    });

    const authUrl = getGoogleAuthUrl(state, codeChallenge, nonce);
    return res.redirect(authUrl);
  } catch (err) {
    return res.redirect(`${config.client.url}/login?error=oauth_init_failed`);
  }
});


/* ----------------------------
 * GOOGLE CALLBACK (FIXED)
 * ---------------------------- */
router.get('/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.redirect(`${config.client.url}/login?error=missing_params`);
    }

    const stored = oauthStates.get(state);
    if (!stored) {
      return res.redirect(`${config.client.url}/login?error=invalid_state`);
    }

    oauthStates.delete(state);

    const tokens = await getGoogleTokens(code, stored.codeVerifier);
    const googleUser = await getGoogleUser(tokens.access_token);

    let user = await User.findOne({ email: googleUser.email });

    if (!user) {
      user = new User({
        name: googleUser.name,
        email: googleUser.email,
        provider: 'google',
        providerId: googleUser.id,
        avatar: googleUser.picture,
        isActive: true,
        isEmailVerified: true,
        loginCount: 0
      });

      user.addAuditLog('account_created', { provider: 'google' }, req);
    } else {
      user.lastLogin = new Date();
      user.loginCount += 1;
    }

    const accessToken = generateAccessToken(user._id, user.role);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = refreshToken;
    await user.save();

    setTokenCookies(res, accessToken, refreshToken);

    // FIXED REDIRECT
    const redirectUrl = `${config.client.url}${stored.returnTo || '/dashboard'}`;
    return res.redirect(redirectUrl);

  } catch (err) {
    console.error(err);
    return res.redirect(`${config.client.url}/login?error=oauth_failed`);
  }
});


/* ----------------------------
 * NORMAL LOGIN / SIGNUP (unchanged)
 * ---------------------------- */

router.post('/signup', signupRateLimit, validateSignup, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const user = new User({
      name,
      email,
      password,
      provider: 'local',
      role: 'user',
      isActive: true
    });

    await user.save();

    const access = generateAccessToken(user._id);
    const refresh = generateRefreshToken(user._id);

    user.refreshToken = refresh;
    await user.save();

    setTokenCookies(res, access, refresh);

    res.json({ user: user.toJSON() });

  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
});


router.post('/login', authRateLimit, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await user.comparePassword(password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const access = generateAccessToken(user._id, user.role);
    const refresh = generateRefreshToken(user._id);

    user.refreshToken = refresh;
    await user.save();

    setTokenCookies(res, access, refresh);

    res.json({ user: user.toJSON() });

  } catch (err) {
    res.status(500).json({ error: 'Failed to login' });
  }
});


/* ----------------------------
 * GET SESSION
 * ---------------------------- */
router.get('/me', requireAuth, requireActive, (req, res) => {
  res.json({ user: req.user });
});


/* ----------------------------
 * LOGOUT
 * ---------------------------- */
router.post('/logout', requireAuth, async (req, res) => {
  try {
    req.user.refreshToken = null;
    await req.user.save();

    clearTokenCookies(res);
    res.json({ message: 'Logged out successfully' });

  } catch (err) {
    res.status(500).json({ error: 'Failed to logout' });
  }
});


module.exports = router;
