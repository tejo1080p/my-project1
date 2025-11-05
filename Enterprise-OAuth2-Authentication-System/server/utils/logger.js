const crypto = require('crypto');

/**
 * Centralized audit logging service with correlation IDs
 */
class Logger {
  constructor() {
    this.logs = [];
    this.maxLogs = 10000; // Keep last 10k logs in memory (use external service in production)
  }

  /**
   * Generate correlation ID for request tracing
   */
  generateCorrelationId() {
    return crypto.randomUUID();
  }

  /**
   * Format log entry
   */
  formatLog(level, message, metadata = {}) {
    return {
      timestamp: new Date().toISOString(),
      level,
      message,
      correlationId: metadata.correlationId || this.generateCorrelationId(),
      userId: metadata.userId || null,
      action: metadata.action || null,
      ip: metadata.ip || null,
      userAgent: metadata.userAgent || null,
      duration: metadata.duration || null,
      status: metadata.status || null,
      error: metadata.error || null,
      details: metadata.details || null
    };
  }

  /**
   * Log authentication events
   */
  logAuth(action, success, metadata = {}) {
    const log = this.formatLog(
      success ? 'info' : 'warn',
      `Authentication: ${action}`,
      {
        ...metadata,
        action,
        status: success ? 'success' : 'failure'
      }
    );
    
    this.store(log);
    
    if (process.env.NODE_ENV !== 'test') {
      console.log(JSON.stringify(log));
    }
    
    return log.correlationId;
  }

  /**
   * Log security events
   */
  logSecurity(action, severity, metadata = {}) {
    const log = this.formatLog(
      severity,
      `Security: ${action}`,
      {
        ...metadata,
        action
      }
    );
    
    this.store(log);
    
    if (process.env.NODE_ENV !== 'test') {
      console.warn(JSON.stringify(log));
    }
    
    return log.correlationId;
  }

  /**
   * Log general info
   */
  info(message, metadata = {}) {
    const log = this.formatLog('info', message, metadata);
    this.store(log);
    
    if (process.env.NODE_ENV !== 'test') {
      console.log(JSON.stringify(log));
    }
    
    return log.correlationId;
  }

  /**
   * Log warnings
   */
  warn(message, metadata = {}) {
    const log = this.formatLog('warn', message, metadata);
    this.store(log);
    
    if (process.env.NODE_ENV !== 'test') {
      console.warn(JSON.stringify(log));
    }
    
    return log.correlationId;
  }

  /**
   * Log errors
   */
  error(message, error, metadata = {}) {
    const log = this.formatLog('error', message, {
      ...metadata,
      error: {
        message: error?.message,
        stack: error?.stack,
        code: error?.code
      }
    });
    
    this.store(log);
    
    if (process.env.NODE_ENV !== 'test') {
      console.error(JSON.stringify(log));
    }
    
    return log.correlationId;
  }

  /**
   * Store log in memory (use external service like ELK, Datadog in production)
   */
  store(log) {
    this.logs.push(log);
    
    // Keep only recent logs
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
  }

  /**
   * Get logs by correlation ID
   */
  getByCorrelationId(correlationId) {
    return this.logs.filter(log => log.correlationId === correlationId);
  }

  /**
   * Get logs by user ID
   */
  getByUserId(userId) {
    return this.logs.filter(log => log.userId === userId);
  }

  /**
   * Get logs by action
   */
  getByAction(action) {
    return this.logs.filter(log => log.action === action);
  }

  /**
   * Get failed authentication attempts
   */
  getFailedAuthAttempts(ip, timeWindow = 15 * 60 * 1000) {
    const since = new Date(Date.now() - timeWindow);
    return this.logs.filter(log => 
      log.ip === ip &&
      log.action &&
      (log.action.includes('login') || log.action.includes('auth')) &&
      log.status === 'failure' &&
      new Date(log.timestamp) > since
    );
  }

  /**
   * Get metrics
   */
  getMetrics(timeWindow = 60 * 60 * 1000) {
    const since = new Date(Date.now() - timeWindow);
    const recentLogs = this.logs.filter(log => new Date(log.timestamp) > since);
    
    return {
      total: recentLogs.length,
      byLevel: {
        info: recentLogs.filter(l => l.level === 'info').length,
        warn: recentLogs.filter(l => l.level === 'warn').length,
        error: recentLogs.filter(l => l.level === 'error').length
      },
      authSuccesses: recentLogs.filter(l => l.action?.includes('auth') && l.status === 'success').length,
      authFailures: recentLogs.filter(l => l.action?.includes('auth') && l.status === 'failure').length,
      topActions: this.getTopActions(recentLogs),
      topIPs: this.getTopIPs(recentLogs)
    };
  }

  /**
   * Get top actions
   */
  getTopActions(logs) {
    const actionCounts = {};
    logs.forEach(log => {
      if (log.action) {
        actionCounts[log.action] = (actionCounts[log.action] || 0) + 1;
      }
    });
    
    return Object.entries(actionCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([action, count]) => ({ action, count }));
  }

  /**
   * Get top IPs
   */
  getTopIPs(logs) {
    const ipCounts = {};
    logs.forEach(log => {
      if (log.ip) {
        ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
      }
    });
    
    return Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));
  }
}

// Singleton instance
const logger = new Logger();

/**
 * Express middleware to add correlation ID to requests
 */
const correlationMiddleware = (req, res, next) => {
  req.correlationId = req.headers['x-correlation-id'] || logger.generateCorrelationId();
  res.setHeader('X-Correlation-ID', req.correlationId);
  next();
};

module.exports = {
  logger,
  correlationMiddleware
};

