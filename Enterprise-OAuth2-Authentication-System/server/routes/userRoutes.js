const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { requireAuth } = require('../middleware/authMiddleware');
const { requireOwnershipOrAdmin, requireActive } = require('../middleware/rbac');
const { validateProfileUpdate, validateConsent, validateProvider } = require('../middleware/validation');
const { apiRateLimit } = require('../middleware/rateLimit');
const { logger } = require('../utils/logger');
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

// In-memory store for linking OAuth state (use Redis in production)
const linkingStates = new Map();

// Clean up old states periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of linkingStates.entries()) {
    if (now - value.timestamp > 10 * 60 * 1000) {
      linkingStates.delete(key);
    }
  }
}, 60 * 1000);

/**
 * Get current user profile
 */
router.get('/profile', requireAuth, requireActive, (req, res) => {
  logger.info('User profile fetched', {
    correlationId: req.correlationId,
    userId: req.user._id,
    action: 'profile_view'
  });

  res.json({ 
    user: req.user,
    permissions: {
      role: req.user.role,
      claims: req.user.claims,
      isAdmin: req.user.role === 'admin'
    }
  });
});

/**
 * Update user profile
 */
router.patch('/profile', requireAuth, requireActive, apiRateLimit, validateProfileUpdate, async (req, res) => {
  try {
    const { name, bio, location, website, avatar } = req.body;
    const user = req.user;

    // Update allowed fields
    if (name !== undefined) user.name = name;
    if (bio !== undefined) user.bio = bio;
    if (location !== undefined) user.location = location;
    if (website !== undefined) user.website = website;
    if (avatar !== undefined) user.avatar = avatar;

    // Add audit log
    user.addAuditLog('profile_update', { 
      fields: Object.keys(req.body) 
    }, req);

    await user.save();

    logger.info('User profile updated', {
      correlationId: req.correlationId,
      userId: user._id,
      action: 'profile_update',
      fields: Object.keys(req.body)
    });

    res.json({ 
      message: 'Profile updated successfully',
      user: user.toJSON()
    });
  } catch (error) {
    logger.error('Profile update failed', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'profile_update'
    });

    res.status(500).json({ error: 'Failed to update profile' });
  }
});

/**
 * Update user consents
 */
router.patch('/consents', requireAuth, requireActive, validateConsent, async (req, res) => {
  try {
    const { profileSync, dataProcessing, marketing } = req.body;
    const user = req.user;

    // Update consents
    if (profileSync !== undefined) user.consents.profileSync = profileSync;
    if (dataProcessing !== undefined) user.consents.dataProcessing = dataProcessing;
    if (marketing !== undefined) user.consents.marketing = marketing;

    // Add audit log
    user.addAuditLog('consent_update', { 
      consents: req.body 
    }, req);

    await user.save();

    logger.info('User consents updated', {
      correlationId: req.correlationId,
      userId: user._id,
      action: 'consent_update',
      consents: req.body
    });

    res.json({ 
      message: 'Consents updated successfully',
      consents: user.consents
    });
  } catch (error) {
    logger.error('Consent update failed', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'consent_update'
    });

    res.status(500).json({ error: 'Failed to update consents' });
  }
});

/**
 * Get linked providers
 */
router.get('/linked-providers', requireAuth, requireActive, (req, res) => {
  res.json({ 
    primary: {
      provider: req.user.provider,
      providerId: req.user.providerId
    },
    linked: req.user.linkedProviders || []
  });
});

/**
 * Initiate provider linking
 */
router.get('/link/:provider', requireAuth, requireActive, validateProvider, (req, res) => {
  try {
    const { provider } = req.params;
    const user = req.user;

    // Check if already linked
    if (user.hasLinkedProvider(provider)) {
      return res.status(400).json({ 
        error: `${provider} account is already linked`,
        code: 'PROVIDER_ALREADY_LINKED'
      });
    }

    // Generate state and nonce
    const state = generateState();
    const nonce = generateNonce();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Store state with user ID
    linkingStates.set(state, {
      userId: user._id.toString(),
      provider,
      codeVerifier,
      nonce,
      timestamp: Date.now(),
      action: 'link'
    });

    logger.info('Provider linking initiated', {
      correlationId: req.correlationId,
      userId: user._id,
      action: 'link_provider_init',
      provider
    });

    // Redirect to OAuth provider
    let authUrl;
    if (provider === 'google') {
      authUrl = getGoogleAuthUrl(state, codeChallenge, nonce);
    } else if (provider === 'facebook') {
      authUrl = getFacebookAuthUrl(state, codeChallenge, nonce);
    }

    res.json({ authUrl });
  } catch (error) {
    logger.error('Provider linking initiation failed', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'link_provider_init',
      provider: req.params.provider
    });

    res.status(500).json({ error: 'Failed to initiate provider linking' });
  }
});

/**
 * Complete provider linking (callback)
 */
router.get('/link/:provider/callback', requireAuth, requireActive, validateProvider, async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state, error } = req.query;
    const user = req.user;

    if (error) {
      return res.redirect(`${process.env.CLIENT_URL}/settings?error=${error}`);
    }

    if (!code || !state) {
      return res.redirect(`${process.env.CLIENT_URL}/settings?error=missing_params`);
    }

    // Verify state
    const storedData = linkingStates.get(state);
    if (!storedData || storedData.provider !== provider || storedData.userId !== user._id.toString()) {
      return res.redirect(`${process.env.CLIENT_URL}/settings?error=invalid_state`);
    }

    // Delete used state
    linkingStates.delete(state);

    // Exchange code for tokens and get user info
    let providerUser;
    if (provider === 'google') {
      const tokens = await getGoogleTokens(code, storedData.codeVerifier);
      providerUser = await getGoogleUser(tokens.access_token);
    } else if (provider === 'facebook') {
      const tokens = await getFacebookTokens(code, storedData.codeVerifier);
      providerUser = await getFacebookUser(tokens.access_token);
    }

    // Check if provider account is already linked to another user
    const existingUser = await User.findOne({
      'linkedProviders.providerId': providerUser.id,
      'linkedProviders.provider': provider,
      _id: { $ne: user._id }
    });

    if (existingUser) {
      logger.warn('Provider already linked to another account', {
        correlationId: req.correlationId,
        userId: user._id,
        action: 'link_provider_complete',
        provider,
        status: 'failure'
      });

      return res.redirect(`${process.env.CLIENT_URL}/settings?error=provider_already_linked`);
    }

    // Link provider
    const profileUrl = provider === 'google' ? 
      providerUser.picture : 
      providerUser.picture?.data?.url;

    user.linkProvider(provider, providerUser.id, providerUser.email, profileUrl);
    
    // Add audit log
    user.addAuditLog('provider_linked', { 
      provider,
      email: providerUser.email 
    }, req);

    await user.save();

    logger.logAuth('link_provider', true, {
      correlationId: req.correlationId,
      userId: user._id,
      provider,
      details: { email: providerUser.email }
    });

    res.redirect(`${process.env.CLIENT_URL}/settings?success=provider_linked&provider=${provider}`);
  } catch (error) {
    logger.error('Provider linking completion failed', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'link_provider_complete',
      provider: req.params.provider
    });

    res.redirect(`${process.env.CLIENT_URL}/settings?error=linking_failed`);
  }
});

/**
 * Unlink provider
 */
router.delete('/link/:provider', requireAuth, requireActive, validateProvider, async (req, res) => {
  try {
    const { provider } = req.params;
    const user = req.user;

    // Prevent unlinking if it's the only authentication method
    if (user.linkedProviders.length === 0 && user.provider === provider && !user.password) {
      return res.status(400).json({ 
        error: 'Cannot unlink the only authentication method. Add a password or link another provider first.',
        code: 'LAST_AUTH_METHOD'
      });
    }

    if (!user.hasLinkedProvider(provider) && user.provider !== provider) {
      return res.status(400).json({ 
        error: `${provider} account is not linked`,
        code: 'PROVIDER_NOT_LINKED'
      });
    }

    // Unlink provider
    user.unlinkProvider(provider);

    // If unlinking primary provider, update to local or first linked provider
    if (user.provider === provider) {
      if (user.linkedProviders.length > 0) {
        const firstLinked = user.linkedProviders[0];
        user.provider = firstLinked.provider;
        user.providerId = firstLinked.providerId;
      } else {
        user.provider = 'local';
        user.providerId = null;
      }
    }

    // Add audit log
    user.addAuditLog('provider_unlinked', { provider }, req);

    await user.save();

    logger.logAuth('unlink_provider', true, {
      correlationId: req.correlationId,
      userId: user._id,
      provider
    });

    res.json({ 
      message: `${provider} account unlinked successfully`,
      linkedProviders: user.linkedProviders
    });
  } catch (error) {
    logger.error('Provider unlinking failed', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'unlink_provider',
      provider: req.params.provider
    });

    res.status(500).json({ error: 'Failed to unlink provider' });
  }
});

/**
 * Get user audit log
 */
router.get('/audit-log', requireAuth, requireActive, (req, res) => {
  const limit = parseInt(req.query.limit || '50', 10);
  const auditLog = req.user.auditLog.slice(-limit).reverse();

  res.json({ auditLog });
});

/**
 * Delete user account
 */
router.delete('/account', requireAuth, requireActive, async (req, res) => {
  try {
    const user = req.user;

    logger.logAuth('account_delete', true, {
      correlationId: req.correlationId,
      userId: user._id,
      email: user.email
    });

    await User.deleteOne({ _id: user._id });

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    logger.error('Account deletion failed', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'account_delete'
    });

    res.status(500).json({ error: 'Failed to delete account' });
  }
});

module.exports = router;

