/**
 * Database seeding script for development and testing
 * 
 * Creates:
 * - Test users with different roles
 * - Sample audit logs
 * - Linked provider accounts
 * 
 * Usage: node scripts/seed.js
 */

const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('../models/User');

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/oauth-social-login';

const seedUsers = [
  {
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'Admin123!',
    role: 'admin',
    provider: 'local',
    isActive: true,
    isEmailVerified: true,
    claims: ['read:users', 'write:users', 'delete:users', 'read:audit', 'write:settings', 'manage:roles'],
    bio: 'System administrator with full access',
    location: 'San Francisco, CA'
  },
  {
    name: 'Moderator User',
    email: 'moderator@example.com',
    password: 'Moderator123!',
    role: 'moderator',
    provider: 'local',
    isActive: true,
    isEmailVerified: true,
    claims: ['read:users', 'read:audit'],
    bio: 'Content moderator',
    location: 'New York, NY'
  },
  {
    name: 'Regular User',
    email: 'user@example.com',
    password: 'User123!',
    role: 'user',
    provider: 'local',
    isActive: true,
    isEmailVerified: true,
    bio: 'Regular platform user',
    location: 'Austin, TX',
    website: 'https://example.com'
  },
  {
    name: 'Google User',
    email: 'google@example.com',
    password: null,
    role: 'user',
    provider: 'google',
    providerId: 'google-123456',
    avatar: 'https://lh3.googleusercontent.com/a/default-user',
    isActive: true,
    isEmailVerified: true,
    linkedProviders: [{
      provider: 'google',
      providerId: 'google-123456',
      email: 'google@example.com',
      profileUrl: 'https://lh3.googleusercontent.com/a/default-user',
      linkedAt: new Date()
    }]
  },
  {
    name: 'Facebook User',
    email: 'facebook@example.com',
    password: null,
    role: 'user',
    provider: 'facebook',
    providerId: 'facebook-789012',
    avatar: 'https://graph.facebook.com/789012/picture',
    isActive: true,
    isEmailVerified: true,
    linkedProviders: [{
      provider: 'facebook',
      providerId: 'facebook-789012',
      email: 'facebook@example.com',
      profileUrl: 'https://graph.facebook.com/789012/picture',
      linkedAt: new Date()
    }]
  },
  {
    name: 'Multi-Provider User',
    email: 'multi@example.com',
    password: 'Multi123!',
    role: 'user',
    provider: 'local',
    isActive: true,
    isEmailVerified: true,
    linkedProviders: [
      {
        provider: 'google',
        providerId: 'google-multi-123',
        email: 'multi@example.com',
        profileUrl: 'https://lh3.googleusercontent.com/a/multi-user',
        linkedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // 7 days ago
      },
      {
        provider: 'facebook',
        providerId: 'facebook-multi-456',
        email: 'multi@example.com',
        profileUrl: 'https://graph.facebook.com/multi-456/picture',
        linkedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000) // 3 days ago
      }
    ],
    bio: 'User with multiple linked OAuth providers',
    location: 'Seattle, WA'
  },
  {
    name: 'Inactive User',
    email: 'inactive@example.com',
    password: 'Inactive123!',
    role: 'user',
    provider: 'local',
    isActive: false,
    isEmailVerified: true,
    bio: 'This account has been deactivated'
  }
];

async function seed() {
  try {
    console.log('🌱 Starting database seed...\n');

    // Connect to database
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('✅ Connected to MongoDB');

    // Clear existing users (optional - comment out to keep existing data)
    const clearExisting = process.argv.includes('--clear');
    if (clearExisting) {
      await User.deleteMany({});
      console.log('🗑️  Cleared existing users');
    }

    // Create users
    const createdUsers = [];
    for (const userData of seedUsers) {
      // Check if user already exists
      const existing = await User.findOne({ email: userData.email });
      if (existing) {
        console.log(`⏭️  User already exists: ${userData.email}`);
        createdUsers.push(existing);
        continue;
      }

      const user = new User({
        ...userData,
        loginCount: Math.floor(Math.random() * 20),
        lastLogin: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Random within last 30 days
        consents: {
          profileSync: true,
          dataProcessing: true,
          marketing: Math.random() > 0.5
        }
      });

      // Add sample audit logs
      const auditActions = [
        { action: 'account_created', details: { method: userData.provider } },
        { action: 'login_success', details: { method: userData.provider } },
        { action: 'profile_update', details: { fields: ['bio'] } }
      ];

      for (const audit of auditActions) {
        user.addAuditLog(audit.action, audit.details, {
          ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          headers: {
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
          },
          correlationId: require('crypto').randomUUID()
        });
      }

      await user.save();
      createdUsers.push(user);
      console.log(`✅ Created user: ${userData.email} (${userData.role})`);
    }

    // Print summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 Seed Summary:');
    console.log('='.repeat(60));
    console.log(`Total users: ${createdUsers.length}`);
    console.log(`Admins: ${createdUsers.filter(u => u.role === 'admin').length}`);
    console.log(`Moderators: ${createdUsers.filter(u => u.role === 'moderator').length}`);
    console.log(`Regular users: ${createdUsers.filter(u => u.role === 'user').length}`);
    console.log(`Active: ${createdUsers.filter(u => u.isActive).length}`);
    console.log(`Inactive: ${createdUsers.filter(u => !u.isActive).length}`);
    console.log('='.repeat(60));

    console.log('\n📝 Test Credentials:');
    console.log('='.repeat(60));
    seedUsers.filter(u => u.password).forEach(u => {
      console.log(`${u.role.toUpperCase().padEnd(10)} | ${u.email.padEnd(25)} | ${u.password}`);
    });
    console.log('='.repeat(60));

    console.log('\n🎉 Database seeded successfully!\n');

    process.exit(0);
  } catch (error) {
    console.error('❌ Seed failed:', error);
    process.exit(1);
  }
}

// Run seed
seed();

