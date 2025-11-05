const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');
const mockOAuthRoutes = require('./routes/mockOAuth');
const avatarProxyRoutes = require('./routes/avatarProxy');
const { correlationMiddleware } = require('./utils/logger');
const { config } = require('./config/environment');

dotenv.config();

const app = express();

// Correlation ID middleware (first)
app.use(correlationMiddleware);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS configuration
app.use(cors(config.cors));

// MongoDB connection
mongoose.connect(config.database.uri, config.database.options)
.then(() => {
  console.log('✅ MongoDB connected successfully');
  console.log(`📊 Database: ${config.database.uri.split('@')[1] || config.database.uri.split('//')[1]}`);
})
.catch((err) => console.error('❌ MongoDB connection error:', err));

// Routes
app.use('/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/avatar', avatarProxyRoutes);

// Mock OAuth (development only)
if (config.features.mockOAuth) {
  app.use('/mock-oauth', mockOAuthRoutes);
}

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: config.environment,
    features: {
      google: config.google.enabled,
      facebook: config.facebook.enabled
    }
  });
});

// Configuration endpoint (development only)
if (config.isDevelopment) {
  app.get('/config', (req, res) => {
    res.json(config.toObject());
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

const PORT = config.server.port;

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 OAuth Authentication Server');
  console.log('='.repeat(60));
  console.log(`📍 Server URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${config.environment}`);
  console.log(`👤 Client URL: ${config.client.url}`);
  console.log(`🔐 Google OAuth: ${config.google.enabled ? '✅ Enabled' : '❌ Disabled'}`);
  console.log(`🔐 Facebook OAuth: ${config.facebook.enabled ? '✅ Enabled' : '❌ Disabled'}`);
  console.log(`🛡️  CSRF Protection: ${config.security.csrfEnabled ? '✅ Enabled' : '❌ Disabled'}`);
  console.log(`📝 Audit Logging: ${config.features.auditLog ? '✅ Enabled' : '❌ Disabled'}`);
  console.log('='.repeat(60) + '\n');

  // Print configuration in development
  if (config.isDevelopment) {
    console.log('💡 Development mode features:');
    console.log('   - Mock OAuth available');
    console.log('   - Configuration endpoint: /config');
    console.log('   - Detailed error messages');
    console.log('');
  }
});

