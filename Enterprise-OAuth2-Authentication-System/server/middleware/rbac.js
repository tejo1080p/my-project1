/**
 * Role-Based Access Control (RBAC) middleware
 * 
 * Provides fine-grained access control based on user roles and claims
 */

/**
 * Require specific role(s)
 */
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: allowedRoles,
        current: req.user.role
      });
    }

    next();
  };
};

/**
 * Require admin role
 */
const requireAdmin = requireRole('admin');

/**
 * Require moderator or admin role
 */
const requireModerator = requireRole('admin', 'moderator');

/**
 * Require specific claim(s)
 */
const requireClaim = (...requiredClaims) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Admins bypass claim checks
    if (req.user.role === 'admin') {
      return next();
    }

    // Check if user has at least one of the required claims
    const hasClaim = requiredClaims.some(claim => 
      req.user.claims && req.user.claims.includes(claim)
    );

    if (!hasClaim) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_CLAIMS',
        required: requiredClaims,
        current: req.user.claims || []
      });
    }

    next();
  };
};

/**
 * Require ALL specified claims
 */
const requireAllClaims = (...requiredClaims) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Admins bypass claim checks
    if (req.user.role === 'admin') {
      return next();
    }

    // Check if user has all required claims
    const hasAllClaims = requiredClaims.every(claim => 
      req.user.claims && req.user.claims.includes(claim)
    );

    if (!hasAllClaims) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_CLAIMS',
        required: requiredClaims,
        current: req.user.claims || []
      });
    }

    next();
  };
};

/**
 * Require ownership or admin
 * Use this to ensure users can only access/modify their own resources
 */
const requireOwnershipOrAdmin = (userIdParam = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Admin can access any resource
    if (req.user.role === 'admin') {
      return next();
    }

    // Get user ID from params, body, or query
    const targetUserId = req.params[userIdParam] || 
                        req.body[userIdParam] || 
                        req.query[userIdParam];

    // Check if user is accessing their own resource
    if (targetUserId && targetUserId !== req.user._id.toString()) {
      return res.status(403).json({ 
        error: 'You can only access your own resources',
        code: 'OWNERSHIP_REQUIRED'
      });
    }

    next();
  };
};

/**
 * Check if user is active
 */
const requireActive = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  if (!req.user.isActive) {
    return res.status(403).json({ 
      error: 'Account is inactive',
      code: 'ACCOUNT_INACTIVE'
    });
  }

  next();
};

/**
 * Check if email is verified (optional enforcement)
 */
const requireVerifiedEmail = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  if (!req.user.isEmailVerified) {
    return res.status(403).json({ 
      error: 'Email verification required',
      code: 'EMAIL_NOT_VERIFIED'
    });
  }

  next();
};

/**
 * Optional role check (doesn't block, just adds permission info to request)
 */
const checkRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (req.user && allowedRoles.includes(req.user.role)) {
      req.hasRole = true;
    } else {
      req.hasRole = false;
    }
    next();
  };
};

/**
 * Get user permissions summary
 */
const getPermissions = (user) => {
  if (!user) {
    return {
      role: 'anonymous',
      claims: [],
      isAdmin: false,
      isModerator: false
    };
  }

  return {
    role: user.role,
    claims: user.claims || [],
    isAdmin: user.role === 'admin',
    isModerator: user.role === 'moderator' || user.role === 'admin',
    isActive: user.isActive,
    isEmailVerified: user.isEmailVerified
  };
};

/**
 * Middleware to add permissions to response
 */
const addPermissionsToResponse = (req, res, next) => {
  res.locals.permissions = getPermissions(req.user);
  next();
};

module.exports = {
  requireRole,
  requireAdmin,
  requireModerator,
  requireClaim,
  requireAllClaims,
  requireOwnershipOrAdmin,
  requireActive,
  requireVerifiedEmail,
  checkRole,
  getPermissions,
  addPermissionsToResponse
};

