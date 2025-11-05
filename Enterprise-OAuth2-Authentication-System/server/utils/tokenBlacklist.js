const crypto = require('crypto');

/**
 * Token blacklist service for server-side token invalidation
 * In production, use Redis for distributed systems
 */
class TokenBlacklist {
  constructor() {
    this.blacklist = new Map();
    this.cleanupInterval = 60 * 60 * 1000; // 1 hour
    
    // Start periodic cleanup
    this.startCleanup();
  }

  /**
   * Add token to blacklist
   */
  add(token, expiresAt) {
    const tokenHash = this.hashToken(token);
    this.blacklist.set(tokenHash, {
      addedAt: Date.now(),
      expiresAt: expiresAt || Date.now() + 24 * 60 * 60 * 1000 // 24 hours default
    });
  }

  /**
   * Check if token is blacklisted
   */
  isBlacklisted(token) {
    const tokenHash = this.hashToken(token);
    const entry = this.blacklist.get(tokenHash);
    
    if (!entry) return false;
    
    // If token expired, remove from blacklist
    if (Date.now() > entry.expiresAt) {
      this.blacklist.delete(tokenHash);
      return false;
    }
    
    return true;
  }

  /**
   * Remove token from blacklist
   */
  remove(token) {
    const tokenHash = this.hashToken(token);
    return this.blacklist.delete(tokenHash);
  }

  /**
   * Hash token for storage (don't store raw tokens)
   */
  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Blacklist all tokens for a user (useful for logout all devices)
   */
  blacklistUserTokens(userId, tokens) {
    tokens.forEach(token => {
      this.add(token, Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    });
  }

  /**
   * Clean up expired tokens
   */
  cleanup() {
    const now = Date.now();
    let removed = 0;
    
    for (const [tokenHash, entry] of this.blacklist.entries()) {
      if (now > entry.expiresAt) {
        this.blacklist.delete(tokenHash);
        removed++;
      }
    }
    
    if (removed > 0) {
      console.log(`[TokenBlacklist] Cleaned up ${removed} expired tokens`);
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
   * Get statistics
   */
  getStats() {
    return {
      total: this.blacklist.size,
      oldest: Math.min(...Array.from(this.blacklist.values()).map(e => e.addedAt)),
      newest: Math.max(...Array.from(this.blacklist.values()).map(e => e.addedAt))
    };
  }

  /**
   * Clear all (for testing)
   */
  clear() {
    this.blacklist.clear();
  }
}

// Singleton instance
const tokenBlacklist = new TokenBlacklist();

module.exports = { tokenBlacklist };

