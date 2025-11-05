/**
 * Mock OAuth provider for local development and testing
 * 
 * Simulates Google and Facebook OAuth flows without requiring actual credentials
 * Only available in development mode
 */

const express = require('express');
const router = express.Router();
const { config } = require('../config/environment');

// Only enable in development
if (!config.features.mockOAuth) {
  console.log('⚠️  Mock OAuth is disabled');
  module.exports = router;
  return;
}

console.log('🧪 Mock OAuth provider enabled');

// Mock user database
const mockUsers = {
  google: [
    {
      id: 'google-mock-1',
      email: 'test@gmail.com',
      name: 'Test User (Google)',
      picture: 'https://via.placeholder.com/150?text=G',
      email_verified: true
    },
    {
      id: 'google-mock-2',
      email: 'john.doe@gmail.com',
      name: 'John Doe (Google)',
      picture: 'https://via.placeholder.com/150?text=JD',
      email_verified: true
    }
  ],
  facebook: [
    {
      id: 'facebook-mock-1',
      email: 'test@facebook.com',
      name: 'Test User (Facebook)',
      picture: {
        data: {
          url: 'https://via.placeholder.com/150?text=F'
        }
      }
    },
    {
      id: 'facebook-mock-2',
      email: 'jane.smith@facebook.com',
      name: 'Jane Smith (Facebook)',
      picture: {
        data: {
          url: 'https://via.placeholder.com/150?text=JS'
        }
      }
    }
  ]
};

/**
 * Mock OAuth selection page
 */
router.get('/select/:provider', (req, res) => {
  const { provider } = req.params;
  const { state, code_challenge, nonce, redirect_uri } = req.query;

  if (!['google', 'facebook'].includes(provider)) {
    return res.status(400).send('Invalid provider');
  }

  const users = mockUsers[provider];

  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Mock ${provider.charAt(0).toUpperCase() + provider.slice(1)} Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
          }
          .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          }
          h1 {
            color: #1f2937;
            margin-bottom: 10px;
          }
          .warning {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
          }
          .warning p {
            margin: 0;
            color: #92400e;
          }
          .user-list {
            margin-top: 30px;
          }
          .user-card {
            display: flex;
            align-items: center;
            padding: 15px;
            margin: 10px 0;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
          }
          .user-card:hover {
            border-color: #3b82f6;
            background: #eff6ff;
          }
          .user-card img {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            margin-right: 15px;
          }
          .user-info {
            flex: 1;
          }
          .user-name {
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 4px;
          }
          .user-email {
            color: #6b7280;
            font-size: 14px;
          }
          .btn {
            background: #3b82f6;
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
            border: none;
            font-size: 14px;
            font-weight: 500;
          }
          .info {
            background: #dbeafe;
            border-left: 4px solid #3b82f6;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
          }
          .info p {
            margin: 0;
            color: #1e3a8a;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🧪 Mock ${provider.charAt(0).toUpperCase() + provider.slice(1)} Login</h1>
          
          <div class="warning">
            <p><strong>⚠️ Development Mode:</strong> This is a mock OAuth provider for testing. In production, this will use real ${provider} authentication.</p>
          </div>

          <div class="info">
            <p><strong>ℹ️ Select a test user to sign in:</strong></p>
          </div>

          <div class="user-list">
            ${users.map(user => `
              <form method="POST" action="/mock-oauth/authorize/${provider}" style="margin: 0;">
                <input type="hidden" name="state" value="${state}">
                <input type="hidden" name="code_challenge" value="${code_challenge}">
                <input type="hidden" name="nonce" value="${nonce}">
                <input type="hidden" name="redirect_uri" value="${redirect_uri}">
                <input type="hidden" name="user_id" value="${user.id}">
                <button type="submit" style="all: unset; width: 100%; cursor: pointer;">
                  <div class="user-card">
                    <img src="${user.picture?.data?.url || user.picture}" alt="${user.name}">
                    <div class="user-info">
                      <div class="user-name">${user.name}</div>
                      <div class="user-email">${user.email}</div>
                    </div>
                    <button type="submit" class="btn">Sign In</button>
                  </div>
                </button>
              </form>
            `).join('')}
          </div>
        </div>
      </body>
    </html>
  `);
});

/**
 * Mock authorization endpoint
 */
router.post('/authorize/:provider', express.urlencoded({ extended: true }), (req, res) => {
  const { provider } = req.params;
  const { state, user_id, redirect_uri } = req.body;

  // Generate mock authorization code
  const code = `mock_${provider}_${user_id}_${Date.now()}`;

  // Redirect back with code
  const redirectUrl = redirect_uri || `${config.server.url}/auth/${provider}/callback`;
  res.redirect(`${redirectUrl}?code=${code}&state=${state}`);
});

/**
 * Mock token exchange endpoint
 */
router.post('/token/:provider', express.json(), express.urlencoded({ extended: true }), (req, res) => {
  const { provider } = req.params;
  const { code } = req.body;

  if (!code || !code.startsWith(`mock_${provider}_`)) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  // Extract user ID from code
  const parts = code.split('_');
  const userId = parts.slice(2, -1).join('_');

  // Return mock token
  res.json({
    access_token: `mock_token_${provider}_${userId}_${Date.now()}`,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: provider === 'google' ? 'email profile' : 'email public_profile'
  });
});

/**
 * Mock user info endpoint
 */
router.get('/userinfo/:provider', (req, res) => {
  const { provider } = req.params;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer mock_token_')) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Extract user ID from token
  const token = authHeader.split(' ')[1];
  const parts = token.split('_');
  const userId = parts.slice(3, -1).join('_');

  // Find user
  const user = mockUsers[provider].find(u => u.id === userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json(user);
});

module.exports = router;

