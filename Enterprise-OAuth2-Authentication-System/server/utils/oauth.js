const crypto = require('crypto');
const axios = require('axios');

/**
 * Generate random state for CSRF protection
 */
const generateState = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Generate nonce for replay protection
 */
const generateNonce = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Generate code verifier for PKCE
 */
const generateCodeVerifier = () => {
  return crypto.randomBytes(32).toString('base64url');
};

/**
 * Generate code challenge from verifier
 */
const generateCodeChallenge = (verifier) => {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
};

/**
 * Google OAuth2 configuration
 */
const getGoogleAuthUrl = (state, codeChallenge, nonce, scopes = null) => {
  const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  
  // Default scopes based on environment or use custom scopes
  const defaultScopes = process.env.GOOGLE_SCOPES ? 
    process.env.GOOGLE_SCOPES.split(',') : 
    [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
    ];
  
  const options = {
    redirect_uri: getGoogleRedirectUri(),
    client_id: process.env.GOOGLE_CLIENT_ID,
    access_type: 'offline',
    response_type: 'code',
    prompt: 'consent',
    scope: (scopes || defaultScopes).join(' '),
    state: state,
    nonce: nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  };

  const qs = new URLSearchParams(options);
  return `${rootUrl}?${qs.toString()}`;
};

/**
 * Get Google redirect URI based on environment
 */
const getGoogleRedirectUri = () => {
  return process.env.GOOGLE_REDIRECT_URI || 'http://localhost:5000/auth/google/callback';
};

/**
 * Exchange Google authorization code for tokens
 */
const getGoogleTokens = async (code, codeVerifier) => {
  const url = 'https://oauth2.googleapis.com/token';
  const values = {
    code,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:5000/auth/google/callback',
    grant_type: 'authorization_code',
    code_verifier: codeVerifier
  };

  const response = await axios.post(url, new URLSearchParams(values), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });

  return response.data;
};

/**
 * Get Google user info
 */
const getGoogleUser = async (accessToken) => {
  const response = await axios.get(
    'https://www.googleapis.com/oauth2/v2/userinfo',
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  return response.data;
};

/**
 * Facebook OAuth2 configuration
 */
const getFacebookAuthUrl = (state, codeChallenge, nonce, scopes = null) => {
  const rootUrl = 'https://www.facebook.com/v18.0/dialog/oauth';
  
  // Default scopes based on environment or use custom scopes
  const defaultScopes = process.env.FACEBOOK_SCOPES ? 
    process.env.FACEBOOK_SCOPES.split(',') : 
    ['email', 'public_profile'];
  
  const options = {
    client_id: process.env.FACEBOOK_CLIENT_ID,
    redirect_uri: getFacebookRedirectUri(),
    state: state,
    response_type: 'code',
    scope: (scopes || defaultScopes).join(','),
    nonce: nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  };

  const qs = new URLSearchParams(options);
  return `${rootUrl}?${qs.toString()}`;
};

/**
 * Get Facebook redirect URI based on environment
 */
const getFacebookRedirectUri = () => {
  return process.env.FACEBOOK_REDIRECT_URI || 'http://localhost:5000/auth/facebook/callback';
};

/**
 * Exchange Facebook authorization code for tokens
 */
const getFacebookTokens = async (code, codeVerifier) => {
  const url = 'https://graph.facebook.com/v18.0/oauth/access_token';
  const params = {
    client_id: process.env.FACEBOOK_CLIENT_ID,
    client_secret: process.env.FACEBOOK_CLIENT_SECRET,
    redirect_uri: process.env.FACEBOOK_REDIRECT_URI || 'http://localhost:5000/auth/facebook/callback',
    code: code,
    code_verifier: codeVerifier
  };

  const response = await axios.get(url, { params });
  return response.data;
};

/**
 * Get Facebook user info
 */
const getFacebookUser = async (accessToken) => {
  const url = 'https://graph.facebook.com/me';
  const params = {
    fields: 'id,name,email,picture',
    access_token: accessToken
  };

  const response = await axios.get(url, { params });
  return response.data;
};

module.exports = {
  generateState,
  generateNonce,
  generateCodeVerifier,
  generateCodeChallenge,
  getGoogleAuthUrl,
  getGoogleTokens,
  getGoogleUser,
  getGoogleRedirectUri,
  getFacebookAuthUrl,
  getFacebookTokens,
  getFacebookUser,
  getFacebookRedirectUri
};

