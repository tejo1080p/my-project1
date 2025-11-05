/**
 * Input validation middleware
 * 
 * Provides validation functions for common input patterns
 * to prevent injection attacks and ensure data integrity
 */

const validator = {
  /**
   * Validate email format
   */
  isEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  /**
   * Validate password strength
   */
  isStrongPassword(password, options = {}) {
    const {
      minLength = 8,
      requireUppercase = true,
      requireLowercase = true,
      requireNumbers = true,
      requireSymbols = false
    } = options;

    if (password.length < minLength) {
      return { valid: false, error: `Password must be at least ${minLength} characters` };
    }

    if (requireUppercase && !/[A-Z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one uppercase letter' };
    }

    if (requireLowercase && !/[a-z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one lowercase letter' };
    }

    if (requireNumbers && !/[0-9]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one number' };
    }

    if (requireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one symbol' };
    }

    return { valid: true };
  },

  /**
   * Validate URL
   */
  isURL(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Sanitize string (remove potential XSS)
   */
  sanitize(str) {
    if (typeof str !== 'string') return str;
    
    return str
      .replace(/[<>]/g, '') // Remove angle brackets
      .trim();
  },

  /**
   * Validate name (letters, spaces, hyphens only)
   */
  isValidName(name) {
    const nameRegex = /^[a-zA-Z\s\-']+$/;
    return nameRegex.test(name) && name.length >= 2 && name.length <= 50;
  },

  /**
   * Validate UUID
   */
  isUUID(str) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(str);
  },

  /**
   * Validate MongoDB ObjectId
   */
  isMongoId(str) {
    const mongoIdRegex = /^[0-9a-fA-F]{24}$/;
    return mongoIdRegex.test(str);
  }
};

/**
 * Middleware to validate signup data
 */
const validateSignup = (req, res, next) => {
  const { name, email, password } = req.body;

  // Check required fields
  if (!name || !email || !password) {
    return res.status(400).json({ 
      error: 'Name, email, and password are required',
      code: 'VALIDATION_ERROR'
    });
  }

  // Validate name
  if (!validator.isValidName(name)) {
    return res.status(400).json({ 
      error: 'Name must contain only letters, spaces, and hyphens (2-50 characters)',
      code: 'INVALID_NAME'
    });
  }

  // Validate email
  if (!validator.isEmail(email)) {
    return res.status(400).json({ 
      error: 'Invalid email format',
      code: 'INVALID_EMAIL'
    });
  }

  // Validate password
  const passwordCheck = validator.isStrongPassword(password, {
    minLength: 8,
    requireUppercase: false, // Make it less strict for better UX
    requireLowercase: true,
    requireNumbers: false,
    requireSymbols: false
  });

  if (!passwordCheck.valid) {
    return res.status(400).json({ 
      error: passwordCheck.error,
      code: 'WEAK_PASSWORD'
    });
  }

  // Sanitize inputs
  req.body.name = validator.sanitize(name);
  req.body.email = email.toLowerCase().trim();

  next();
};

/**
 * Middleware to validate login data
 */
const validateLogin = (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      error: 'Email and password are required',
      code: 'VALIDATION_ERROR'
    });
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ 
      error: 'Invalid email format',
      code: 'INVALID_EMAIL'
    });
  }

  req.body.email = email.toLowerCase().trim();

  next();
};

/**
 * Middleware to validate profile update
 */
const validateProfileUpdate = (req, res, next) => {
  const { name, bio, location, website } = req.body;

  if (name !== undefined) {
    if (!validator.isValidName(name)) {
      return res.status(400).json({ 
        error: 'Name must contain only letters, spaces, and hyphens (2-50 characters)',
        code: 'INVALID_NAME'
      });
    }
    req.body.name = validator.sanitize(name);
  }

  if (bio !== undefined) {
    if (bio.length > 500) {
      return res.status(400).json({ 
        error: 'Bio must be 500 characters or less',
        code: 'BIO_TOO_LONG'
      });
    }
    req.body.bio = validator.sanitize(bio);
  }

  if (location !== undefined) {
    if (location.length > 100) {
      return res.status(400).json({ 
        error: 'Location must be 100 characters or less',
        code: 'LOCATION_TOO_LONG'
      });
    }
    req.body.location = validator.sanitize(location);
  }

  if (website !== undefined && website !== '') {
    if (!validator.isURL(website)) {
      return res.status(400).json({ 
        error: 'Invalid website URL',
        code: 'INVALID_URL'
      });
    }
    if (website.length > 200) {
      return res.status(400).json({ 
        error: 'Website URL must be 200 characters or less',
        code: 'URL_TOO_LONG'
      });
    }
  }

  next();
};

/**
 * Middleware to validate role update (admin only)
 */
const validateRoleUpdate = (req, res, next) => {
  const { role, claims } = req.body;

  if (role !== undefined) {
    const validRoles = ['user', 'admin', 'moderator'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ 
        error: 'Invalid role. Must be: user, admin, or moderator',
        code: 'INVALID_ROLE'
      });
    }
  }

  if (claims !== undefined) {
    if (!Array.isArray(claims)) {
      return res.status(400).json({ 
        error: 'Claims must be an array',
        code: 'INVALID_CLAIMS'
      });
    }

    // Validate each claim
    const validClaims = [
      'read:users',
      'write:users',
      'delete:users',
      'read:audit',
      'write:settings',
      'manage:roles'
    ];

    for (const claim of claims) {
      if (!validClaims.includes(claim)) {
        return res.status(400).json({ 
          error: `Invalid claim: ${claim}`,
          code: 'INVALID_CLAIM'
        });
      }
    }
  }

  next();
};

/**
 * Middleware to validate OAuth provider
 */
const validateProvider = (req, res, next) => {
  const { provider } = req.params;
  const validProviders = ['google', 'facebook'];

  if (!validProviders.includes(provider)) {
    return res.status(400).json({ 
      error: 'Invalid OAuth provider',
      code: 'INVALID_PROVIDER'
    });
  }

  next();
};

/**
 * Middleware to validate consent update
 */
const validateConsent = (req, res, next) => {
  const { profileSync, dataProcessing, marketing } = req.body;

  if (profileSync !== undefined && typeof profileSync !== 'boolean') {
    return res.status(400).json({ 
      error: 'profileSync must be a boolean',
      code: 'INVALID_CONSENT'
    });
  }

  if (dataProcessing !== undefined && typeof dataProcessing !== 'boolean') {
    return res.status(400).json({ 
      error: 'dataProcessing must be a boolean',
      code: 'INVALID_CONSENT'
    });
  }

  if (marketing !== undefined && typeof marketing !== 'boolean') {
    return res.status(400).json({ 
      error: 'marketing must be a boolean',
      code: 'INVALID_CONSENT'
    });
  }

  next();
};

module.exports = {
  validator,
  validateSignup,
  validateLogin,
  validateProfileUpdate,
  validateRoleUpdate,
  validateProvider,
  validateConsent
};

