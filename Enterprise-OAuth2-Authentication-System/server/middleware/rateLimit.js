/**
 * Rate limiting middleware to prevent brute force attacks
 * 
 * Uses sliding window algorithm for accurate rate limiting
 * In production, use Redis for distributed rate limiting
 */

class RateLimiter {
  constructor() {
    this.requests = new Map();
    this.cleanupInterval = 60 * 1000; // 1 minute
    
    // Start periodic cleanup
    this.startCleanup();
  }

  /**
   * Check if request should be rate limited
   */
  isRateLimited(key, maxRequests, windowMs) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get existing requests for this key
    let requests = this.requests.get(key) || [];
    
    // Remove old requests outside the window
    requests = requests.filter(timestamp => timestamp > windowStart);
    
    // Check if limit exceeded
    if (requests.length >= maxRequests) {
      return {
        limited: true,
        retryAfter: Math.ceil((requests[0] + windowMs - now) / 1000)
      };
    }
    
    // Add current request
    requests.push(now);
    this.requests.set(key, requests);
    
    return {
      limited: false,
      remaining: maxRequests - requests.length
    };
  }

  /**
   * Clean up old entries
   */
  cleanup() {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000; // 1 hour
    
    for (const [key, requests] of this.requests.entries()) {
      // Remove entries with no recent requests
      const recentRequests = requests.filter(timestamp => now - timestamp < maxAge);
      
      if (recentRequests.length === 0) {
        this.requests.delete(key);
      } else {
        this.requests.set(key, recentRequests);
      }
    }
  }

  /**
   * Start periodic cleanup
   */
  startCleanup() {
    setInterval(() => {
      this.cleanup();
    }, this.cleanupInterval);
  }

  /**
   * Reset rate limit for a key
   */
  reset(key) {
    this.requests.delete(key);
  }

  /**
   * Get stats
   */
  getStats() {
    return {
      totalKeys: this.requests.size,
      keys: Array.from(this.requests.keys())
    };
  }
}

// Singleton instance
const rateLimiter = new RateLimiter();

/**
 * Rate limiting middleware factory
 */
const createRateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    maxRequests = 100,
    keyGenerator = (req) => req.ip || req.connection.remoteAddress,
    skipSuccessfulRequests = false,
    skipFailedRequests = false,
    handler = null
  } = options;

  return (req, res, next) => {
    const key = keyGenerator(req);
    
    if (!key) {
      return next();
    }
    
    const result = rateLimiter.isRateLimited(key, maxRequests, windowMs);
    
    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', result.remaining || 0);
    
    if (result.limited) {
      res.setHeader('Retry-After', result.retryAfter);
      
      if (handler) {
        return handler(req, res, next);
      }
      
      return res.status(429).json({
        error: 'Too many requests',
        retryAfter: result.retryAfter,
        code: 'RATE_LIMIT_EXCEEDED'
      });
    }
    
    // If skip options are enabled, remove from tracking on response
    if (skipSuccessfulRequests || skipFailedRequests) {
      const originalSend = res.send;
      res.send = function(data) {
        const statusCode = res.statusCode;
        
        if (
          (skipSuccessfulRequests && statusCode < 400) ||
          (skipFailedRequests && statusCode >= 400)
        ) {
          // Remove the last request from tracking
          const requests = rateLimiter.requests.get(key) || [];
          requests.pop();
          if (requests.length === 0) {
            rateLimiter.requests.delete(key);
          } else {
            rateLimiter.requests.set(key, requests);
          }
        }
        
        return originalSend.call(this, data);
      };
    }
    
    next();
  };
};

/**
 * Strict rate limiter for authentication endpoints
 */
const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5, // 5 attempts
  keyGenerator: (req) => {
    // Rate limit by IP + email combination for login
    const email = req.body?.email || '';
    const ip = req.ip || req.connection.remoteAddress;
    return `auth:${ip}:${email}`;
  },
  skipSuccessfulRequests: true // Only count failed attempts
});

/**
 * OAuth rate limiter
 */
const oauthRateLimit = createRateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  maxRequests: 10,
  keyGenerator: (req) => {
    const ip = req.ip || req.connection.remoteAddress;
    return `oauth:${ip}`;
  }
});

/**
 * API rate limiter
 */
const apiRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100,
  keyGenerator: (req) => {
    // Rate limit by user ID if authenticated, otherwise by IP
    const userId = req.user?.id;
    const ip = req.ip || req.connection.remoteAddress;
    return userId ? `api:user:${userId}` : `api:ip:${ip}`;
  }
});

/**
 * Signup rate limiter
 */
const signupRateLimit = createRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 3, // 3 signups per hour per IP
  keyGenerator: (req) => {
    const ip = req.ip || req.connection.remoteAddress;
    return `signup:${ip}`;
  }
});

module.exports = {
  rateLimiter,
  createRateLimit,
  authRateLimit,
  oauthRateLimit,
  apiRateLimit,
  signupRateLimit
};

