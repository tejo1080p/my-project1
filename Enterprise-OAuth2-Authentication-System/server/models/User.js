const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Sub-schema for linked OAuth providers
const linkedProviderSchema = new mongoose.Schema({
  provider: {
    type: String,
    enum: ['google', 'facebook'],
    required: true
  },
  providerId: {
    type: String,
    required: true
  },
  email: String,
  profileUrl: String,
  linkedAt: {
    type: Date,
    default: Date.now
  }
}, { _id: false });

// Sub-schema for audit logs
const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true
  },
  details: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String,
  correlationId: String,
  timestamp: {
    type: Date,
    default: Date.now
  }
}, { _id: false });

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    // Required only for manual signup, not for OAuth
    required: function() {
      return this.linkedProviders.length === 0 && !this.provider;
    }
  },
  // Primary authentication provider (legacy field, kept for backwards compatibility)
  provider: {
    type: String,
    enum: ['google', 'facebook', 'local'],
    default: 'local'
  },
  // Primary provider ID (legacy field)
  providerId: {
    type: String,
    sparse: true
  },
  // Array of all linked OAuth providers
  linkedProviders: [linkedProviderSchema],
  // Role-based access control
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  // Custom claims for fine-grained permissions
  claims: {
    type: [String],
    default: []
  },
  avatar: {
    type: String,
    default: ''
  },
  // Editable profile fields
  bio: {
    type: String,
    maxlength: 500,
    default: ''
  },
  location: {
    type: String,
    maxlength: 100,
    default: ''
  },
  website: {
    type: String,
    maxlength: 200,
    default: ''
  },
  // Consent tracking
  consents: {
    profileSync: {
      type: Boolean,
      default: true
    },
    dataProcessing: {
      type: Boolean,
      default: true
    },
    marketing: {
      type: Boolean,
      default: false
    }
  },
  refreshToken: {
    type: String,
    default: null
  },
  // Nonce for replay protection (last used nonces)
  usedNonces: [{
    nonce: String,
    timestamp: Date
  }],
  // Account status
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  // Audit trail
  auditLog: [auditLogSchema],
  lastLogin: {
    type: Date,
    default: Date.now
  },
  lastLoginIp: String,
  loginCount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Index for faster lookups
userSchema.index({ email: 1 });
userSchema.index({ providerId: 1, provider: 1 });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to add audit log entry
userSchema.methods.addAuditLog = function(action, details, req) {
  const auditEntry = {
    action,
    details,
    ip: req?.ip || req?.headers?.['x-forwarded-for'] || 'unknown',
    userAgent: req?.headers?.['user-agent'] || 'unknown',
    correlationId: req?.correlationId || require('crypto').randomUUID(),
    timestamp: new Date()
  };
  
  // Keep only last 100 audit entries
  if (this.auditLog.length >= 100) {
    this.auditLog.shift();
  }
  
  this.auditLog.push(auditEntry);
};

// Method to check if provider is linked
userSchema.methods.hasLinkedProvider = function(provider) {
  return this.linkedProviders.some(p => p.provider === provider);
};

// Method to add linked provider
userSchema.methods.linkProvider = function(provider, providerId, email, profileUrl) {
  // Check if already linked
  if (this.hasLinkedProvider(provider)) {
    return false;
  }
  
  this.linkedProviders.push({
    provider,
    providerId,
    email,
    profileUrl,
    linkedAt: new Date()
  });
  
  return true;
};

// Method to remove linked provider
userSchema.methods.unlinkProvider = function(provider) {
  const index = this.linkedProviders.findIndex(p => p.provider === provider);
  if (index > -1) {
    this.linkedProviders.splice(index, 1);
    return true;
  }
  return false;
};

// Method to check if nonce was used (replay protection)
userSchema.methods.isNonceUsed = function(nonce) {
  // Clean up old nonces (older than 10 minutes)
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
  this.usedNonces = this.usedNonces.filter(n => n.timestamp > tenMinutesAgo);
  
  return this.usedNonces.some(n => n.nonce === nonce);
};

// Method to mark nonce as used
userSchema.methods.markNonceAsUsed = function(nonce) {
  this.usedNonces.push({
    nonce,
    timestamp: new Date()
  });
  
  // Keep only last 50 nonces
  if (this.usedNonces.length > 50) {
    this.usedNonces.shift();
  }
};

// Method to check if user has permission
userSchema.methods.hasPermission = function(claim) {
  if (this.role === 'admin') return true;
  return this.claims.includes(claim);
};

// Method to get public profile
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.refreshToken;
  delete user.usedNonces;
  delete user.__v;
  // Limit audit log in response
  if (user.auditLog && user.auditLog.length > 10) {
    user.auditLog = user.auditLog.slice(-10);
  }
  return user;
};

module.exports = mongoose.model('User', userSchema);

