/**
 * Environment configuration manager
 * Centralizes all environment variables with validation and defaults
 */

const crypto = require('crypto');

class EnvironmentConfig {
  constructor() {
    this.env = process.env.NODE_ENV || 'development';
    this.validateRequired();
  }

  validateRequired() {
    const required = [];

    if (this.env === 'production') {
      if (!process.env.JWT_SECRET || process.env.JWT_SECRET.includes('change-in-production')) {
        required.push('JWT_SECRET');
      }
      if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.includes('change-in-production')) {
        required.push('JWT_REFRESH_SECRET');
      }
      if (!process.env.MONGODB_URI) {
        required.push('MONGODB_URI');
      }
    }

    if (required.length > 0) {
      console.warn(`⚠️ Missing required environment variables: ${required.join(', ')}`);
    }
  }

  get environment() {
    return this.env;
  }

  get isProduction() {
    return this.env === 'production';
  }

  get isDevelopment() {
    return this.env === 'development';
  }

  get isTest() {
    return this.env === 'test';
  }

  get server() {
    return {
      port: parseInt(process.env.PORT || '5000', 10),
      host: process.env.HOST || 'localhost',
      url: process.env.SERVER_URL || `http://localhost:${process.env.PORT || 5000}`
    };
  }

  get client() {
    return {
      url: process.env.CLIENT_URL || 'http://localhost:5173'
    };
  }

  get database() {
    return {
      uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/oauth-social-login',
      options: {
        useNewUrlParser: true,
        useUnifiedTopology: true
      }
    };
  }

  get jwt() {
    return {
      secret: process.env.JWT_SECRET || this.generateDevSecret('access'),
      refreshSecret: process.env.JWT_REFRESH_SECRET || this.generateDevSecret('refresh'),
      accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
      refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d'
    };
  }

  get google() {
    const enabled = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
    return {
      enabled,
      clientId: process.env.GOOGLE_CLIENT_ID || 'GOOGLE_CLIENT_ID_NOT_SET',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'GOOGLE_CLIENT_SECRET_NOT_SET',
      redirectUri: process.env.GOOGLE_REDIRECT_URI || `${this.server.url}/auth/google/callback`,
      scopes: process.env.GOOGLE_SCOPES
        ? process.env.GOOGLE_SCOPES.split(',')
        : [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
          ]
    };
  }

  get facebook() {
    const enabled = !!(process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET);
    return {
      enabled,
      clientId: process.env.FACEBOOK_CLIENT_ID || 'FACEBOOK_CLIENT_ID_NOT_SET',
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET || 'FACEBOOK_CLIENT_SECRET_NOT_SET',
      redirectUri: process.env.FACEBOOK_REDIRECT_URI || `${this.server.url}/auth/facebook/callback`,
      scopes: process.env.FACEBOOK_SCOPES
        ? process.env.FACEBOOK_SCOPES.split(',')
        : ['email', 'public_profile']
    };
  }

  /**
   * ✅ CORS configuration (updated for Render ↔ Vercel)
   */
  get cors() {
    return {
      origin: this.client.url,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-CSRF-Token',
        'X-Correlation-ID'
      ],
      exposedHeaders: ['Set-Cookie']
    };
  }

  /**
   * ✅ Cookie configuration (updated for HTTPS + cross-domain)
   */
  get cookies() {
    return {
      httpOnly: true,
      secure: this.isProduction, // only secure in prod
      sameSite: this.isProduction ? 'none' : 'lax', // allow cross-site cookies
      domain: process.env.COOKIE_DOMAIN || undefined,
      path: '/'
    };
  }

  get rateLimit() {
    return {
      auth: {
        windowMs: 15 * 60 * 1000,
        maxRequests: parseInt(process.env.RATE_LIMIT_AUTH || '5', 10)
      },
      api: {
        windowMs: 15 * 60 * 1000,
        maxRequests: parseInt(process.env.RATE_LIMIT_API || '100', 10)
      },
      oauth: {
        windowMs: 10 * 60 * 1000,
        maxRequests: parseInt(process.env.RATE_LIMIT_OAUTH || '10', 10)
      },
      signup: {
        windowMs: 60 * 60 * 1000,
        maxRequests: parseInt(process.env.RATE_LIMIT_SIGNUP || '3', 10)
      }
    };
  }

  get security() {
    return {
      bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '10', 10),
      csrfEnabled: process.env.CSRF_ENABLED !== 'false',
      sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600000', 10),
      maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5', 10),
      lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900000', 10)
    };
  }

  get features() {
    return {
      emailVerification: process.env.FEATURE_EMAIL_VERIFICATION === 'true',
      twoFactor: process.env.FEATURE_TWO_FACTOR === 'true',
      auditLog: process.env.FEATURE_AUDIT_LOG !== 'false',
      mockOAuth: process.env.MOCK_OAUTH === 'true' || this.isDevelopment
    };
  }

  get logging() {
    return {
      level: process.env.LOG_LEVEL || (this.isProduction ? 'info' : 'debug'),
      format: process.env.LOG_FORMAT || 'json',
      destination: process.env.LOG_DESTINATION || 'console'
    };
  }

  generateDevSecret(type) {
    if (this.isProduction) {
      throw new Error(`${type} secret not set in production!`);
    }
    return crypto.randomBytes(64).toString('hex');
  }

  toObject() {
    return {
      environment: this.environment,
      isProduction: this.isProduction,
      isDevelopment: this.isDevelopment,
      server: this.server,
      client: this.client,
      database: this.database,
      jwt: {
        ...this.jwt,
        secret: '[REDACTED]',
        refreshSecret: '[REDACTED]'
      },
      google: {
        ...this.google,
        clientSecret: this.google.enabled ? '[REDACTED]' : 'NOT_SET'
      },
      facebook: {
        ...this.facebook,
        clientSecret: this.facebook.enabled ? '[REDACTED]' : 'NOT_SET'
      },
      cors: this.cors,
      cookies: this.cookies,
      rateLimit: this.rateLimit,
      security: this.security,
      features: this.features,
      logging: this.logging
    };
  }

  print() {
    console.log('\n📋 Configuration:');
    console.log(JSON.stringify(this.toObject(), null, 2));
    console.log('\n');
  }
}

const config = new EnvironmentConfig();
module.exports = { config };
