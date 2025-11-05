const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { requireAuth } = require('../middleware/authMiddleware');
const { requireAdmin, requireModerator, requireClaim } = require('../middleware/rbac');
const { validateRoleUpdate } = require('../middleware/validation');
const { apiRateLimit } = require('../middleware/rateLimit');
const { logger } = require('../utils/logger');

/**
 * Get all users (admin only)
 */
router.get('/users', requireAuth, requireModerator, apiRateLimit, async (req, res) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '20', 10);
    const search = req.query.search || '';
    const role = req.query.role || null;

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { email: new RegExp(search, 'i') },
        { name: new RegExp(search, 'i') }
      ];
    }
    
    if (role) {
      query.role = role;
    }

    // Get users with pagination
    const users = await User.find(query)
      .select('-password -refreshToken -usedNonces')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    const total = await User.countDocuments(query);

    logger.info('Users list fetched', {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_list_users',
      filters: { search, role, page, limit }
    });

    res.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Failed to fetch users', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_list_users'
    });

    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * Get user by ID (admin/moderator only)
 */
router.get('/users/:userId', requireAuth, requireModerator, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('-password -refreshToken -usedNonces');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info('User details fetched', {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_view_user',
      targetUserId: user._id
    });

    res.json({ user });
  } catch (error) {
    logger.error('Failed to fetch user', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_view_user'
    });

    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

/**
 * Update user role and claims (admin only)
 */
router.patch('/users/:userId/role', requireAuth, requireAdmin, validateRoleUpdate, async (req, res) => {
  try {
    const { role, claims } = req.body;
    const targetUserId = req.params.userId;

    // Prevent self-demotion
    if (targetUserId === req.user._id.toString()) {
      return res.status(400).json({ 
        error: 'Cannot modify your own role',
        code: 'SELF_MODIFICATION_DENIED'
      });
    }

    const user = await User.findById(targetUserId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const oldRole = user.role;
    const oldClaims = [...(user.claims || [])];

    // Update role and claims
    if (role !== undefined) user.role = role;
    if (claims !== undefined) user.claims = claims;

    // Add audit log
    user.addAuditLog('role_updated', { 
      oldRole,
      newRole: role,
      oldClaims,
      newClaims: claims,
      updatedBy: req.user._id
    }, req);

    await user.save();

    logger.logAuth('role_update', true, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_update_role',
      targetUserId: user._id,
      details: { oldRole, newRole: role, claims }
    });

    res.json({ 
      message: 'User role updated successfully',
      user: user.toJSON()
    });
  } catch (error) {
    logger.error('Failed to update user role', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_update_role'
    });

    res.status(500).json({ error: 'Failed to update user role' });
  }
});

/**
 * Activate/deactivate user (admin only)
 */
router.patch('/users/:userId/status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { isActive } = req.body;
    const targetUserId = req.params.userId;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive must be a boolean' });
    }

    // Prevent self-deactivation
    if (targetUserId === req.user._id.toString()) {
      return res.status(400).json({ 
        error: 'Cannot modify your own account status',
        code: 'SELF_MODIFICATION_DENIED'
      });
    }

    const user = await User.findById(targetUserId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.isActive = isActive;

    // Add audit log
    user.addAuditLog('status_updated', { 
      isActive,
      updatedBy: req.user._id
    }, req);

    await user.save();

    logger.logAuth('status_update', true, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_update_status',
      targetUserId: user._id,
      details: { isActive }
    });

    res.json({ 
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
      user: user.toJSON()
    });
  } catch (error) {
    logger.error('Failed to update user status', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_update_status'
    });

    res.status(500).json({ error: 'Failed to update user status' });
  }
});

/**
 * Delete user (admin only)
 */
router.delete('/users/:userId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const targetUserId = req.params.userId;

    // Prevent self-deletion
    if (targetUserId === req.user._id.toString()) {
      return res.status(400).json({ 
        error: 'Cannot delete your own account',
        code: 'SELF_DELETION_DENIED'
      });
    }

    const user = await User.findById(targetUserId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.logAuth('admin_delete_user', true, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_delete_user',
      targetUserId: user._id,
      details: { email: user.email }
    });

    await User.deleteOne({ _id: targetUserId });

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    logger.error('Failed to delete user', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_delete_user'
    });

    res.status(500).json({ error: 'Failed to delete user' });
  }
});

/**
 * Get system statistics (admin only)
 */
router.get('/stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const inactiveUsers = await User.countDocuments({ isActive: false });
    
    const usersByProvider = await User.aggregate([
      { $group: { _id: '$provider', count: { $sum: 1 } } }
    ]);
    
    const usersByRole = await User.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } }
    ]);

    // Get users registered in last 30 days
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentUsers = await User.countDocuments({ 
      createdAt: { $gte: thirtyDaysAgo } 
    });

    // Get audit metrics from logger
    const auditMetrics = logger.getMetrics(60 * 60 * 1000); // Last hour

    res.json({
      users: {
        total: totalUsers,
        active: activeUsers,
        inactive: inactiveUsers,
        recent: recentUsers
      },
      byProvider: usersByProvider,
      byRole: usersByRole,
      audit: auditMetrics
    });
  } catch (error) {
    logger.error('Failed to fetch stats', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_stats'
    });

    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

/**
 * Get audit logs (admin only)
 */
router.get('/audit-logs', requireAuth, requireClaim('read:audit'), async (req, res) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '50', 10);
    const userId = req.query.userId || null;
    const action = req.query.action || null;

    // Build aggregation pipeline
    const pipeline = [];

    // Unwind audit logs
    pipeline.push({ $unwind: '$auditLog' });

    // Match filters
    const matchStage = {};
    if (userId) matchStage['_id'] = userId;
    if (action) matchStage['auditLog.action'] = action;
    
    if (Object.keys(matchStage).length > 0) {
      pipeline.push({ $match: matchStage });
    }

    // Project fields
    pipeline.push({
      $project: {
        userId: '$_id',
        email: '$email',
        name: '$name',
        action: '$auditLog.action',
        details: '$auditLog.details',
        ip: '$auditLog.ip',
        userAgent: '$auditLog.userAgent',
        correlationId: '$auditLog.correlationId',
        timestamp: '$auditLog.timestamp'
      }
    });

    // Sort by timestamp descending
    pipeline.push({ $sort: { timestamp: -1 } });

    // Add pagination
    pipeline.push({ $skip: (page - 1) * limit });
    pipeline.push({ $limit: limit });

    const logs = await User.aggregate(pipeline);

    res.json({
      logs,
      pagination: {
        page,
        limit
      }
    });
  } catch (error) {
    logger.error('Failed to fetch audit logs', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_audit_logs'
    });

    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

/**
 * Get security events from logger (admin only)
 */
router.get('/security-events', requireAuth, requireAdmin, (req, res) => {
  try {
    const timeWindow = parseInt(req.query.timeWindow || '3600000', 10); // 1 hour default
    const metrics = logger.getMetrics(timeWindow);

    res.json(metrics);
  } catch (error) {
    logger.error('Failed to fetch security events', error, {
      correlationId: req.correlationId,
      userId: req.user._id,
      action: 'admin_security_events'
    });

    res.status(500).json({ error: 'Failed to fetch security events' });
  }
});

module.exports = router;

