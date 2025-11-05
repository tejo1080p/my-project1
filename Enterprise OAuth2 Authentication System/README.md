# 🔐 Enterprise OAuth2 Authentication System - MERN Stack

A complete, production-ready OAuth2 social authentication system with advanced security features, role-based access control, audit logging, and enterprise-level observability.

## 🌟 Overview

This is a comprehensive authentication system featuring Google and Facebook OAuth using Authorization Code Flow with PKCE, JWT-based sessions, role-based access control, account linking, profile management, audit logging, and a complete admin panel.

## ✨ Key Features

### Authentication & OAuth
- ✅ **Google & Facebook OAuth** - Authorization Code Flow with PKCE
- ✅ **Email/Password Auth** - Traditional signup and login
- ✅ **Account Linking** - Link multiple OAuth providers to one account
- ✅ **Nonce-based Replay Protection** - Prevents token replay attacks
- ✅ **State Parameter Validation** - CSRF protection for OAuth flows
- ✅ **Redirect-back Support** - Returns to original destination after auth

### Session & Token Management
- ✅ **Short-lived JWT Access Tokens** - 15 minutes, httpOnly cookies
- ✅ **Refresh Token Strategy** - 7-day refresh tokens with rotation
- ✅ **Server-side Token Blacklist** - Invalidate tokens on logout
- ✅ **Logout All Devices** - Revoke all user sessions
- ✅ **Secure Cookies** - httpOnly, SameSite, secure in production

### Security Hardening
- ✅ **CSRF Protection** - Single-use CSRF tokens
- ✅ **Rate Limiting** - Per-endpoint limits with sliding window
- ✅ **Input Validation** - Email, password, URL validation with XSS sanitization
- ✅ **Strict CORS** - Environment-based origin validation
- ✅ **Password Hashing** - Bcrypt with 10 salt rounds
- ✅ **Secrets Management** - Environment-based configuration

### Roles & Permissions
- ✅ **Role-Based Access Control** - User, Moderator, Admin roles
- ✅ **Claim-based Permissions** - Fine-grained access control
- ✅ **Role Assignment on Signup** - Default user role
- ✅ **Admin Upgrades** - Admin-only role management
- ✅ **UI Gating** - Role-based navigation and features

### User Management
- ✅ **Profile Management** - Edit name, bio, location, website
- ✅ **Profile Sync** - Pull name/avatar from OAuth with consent
- ✅ **Consent Management** - Profile sync, data processing, marketing preferences
- ✅ **Account Deletion** - GDPR-compliant data removal
- ✅ **Editable Profile Fields** - Character limits and validation

### Admin Panel
- ✅ **User Management** - List, search, filter users
- ✅ **Role Management** - Update user roles and claims
- ✅ **Account Status Control** - Activate/deactivate users
- ✅ **System Statistics** - Users by role, provider, activity
- ✅ **Audit Log Viewer** - View system-wide audit logs

### Auditing & Observability
- ✅ **Structured Logging** - JSON-formatted logs with severity levels
- ✅ **Correlation IDs** - UUID-based request tracing
- ✅ **Per-user Audit Logs** - Last 100 actions with IP and user agent
- ✅ **Security Event Logging** - Track suspicious activities
- ✅ **Success/Failure Metrics** - Authentication analytics
- ✅ **Admin Analytics** - System health and usage metrics

### Developer Experience
- ✅ **Mock OAuth Provider** - Test without real OAuth credentials
- ✅ **Database Seeding** - Instant test data with multiple roles
- ✅ **Environment Validation** - Catch configuration errors early
- ✅ **Health Check Endpoint** - Monitor system status
- ✅ **Configuration Endpoint** - Debug settings (dev only)

## 🛠️ Tech Stack

**Backend:**
- Node.js & Express.js
- MongoDB & Mongoose
- JWT (jsonwebtoken)
- bcryptjs
- OAuth2 with PKCE
- Axios

**Frontend:**
- React 18
- Vite
- React Router v6
- Axios
- Context API

**Security:**
- CSRF Protection
- Rate Limiting (Sliding Window)
- Input Validation & Sanitization
- Token Blacklist
- Correlation IDs

## 🚀 Quick Start (5 Minutes)

### 1. Install Dependencies

```bash
npm run install-all
```

### 2. Generate JWT Secrets

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 3. Configure Environment

Create `server/.env`:

```env
# Server
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173

# Database
MONGODB_URI=mongodb://localhost:27017/oauth-social-login

# JWT Secrets (paste generated secrets from step 2)
JWT_SECRET=your-generated-secret-here
JWT_REFRESH_SECRET=your-generated-refresh-secret-here

# Optional: Enable mock OAuth for testing without credentials
MOCK_OAUTH=true

# Optional: Google OAuth (not needed if MOCK_OAUTH=true)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback

# Optional: Facebook OAuth (not needed if MOCK_OAUTH=true)
FACEBOOK_CLIENT_ID=your-facebook-app-id
FACEBOOK_CLIENT_SECRET=your-facebook-app-secret
FACEBOOK_REDIRECT_URI=http://localhost:5000/auth/facebook/callback
```

Create `client/.env`:

```env
VITE_API_URL=http://localhost:5000
```

### 4. Start MongoDB

```bash
# macOS
brew services start mongodb-community

# Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Or use MongoDB Atlas (cloud)
```

### 5. Seed Database (Optional but Recommended)

```bash
cd server
npm run seed
```

This creates test users:

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@example.com | Admin123! |
| Moderator | moderator@example.com | Moderator123! |
| User | user@example.com | User123! |

### 6. Start Development Servers

```bash
# From root directory
npm run dev
```

- **Backend**: http://localhost:5000
- **Frontend**: http://localhost:5173

### 7. Test the Application

1. Open http://localhost:5173
2. Click "Sign Up" or use test credentials
3. Try OAuth login (uses mock provider in dev mode)
4. Visit Settings page to manage profile
5. Login as admin to access Admin Panel

## 📁 Project Structure

```
O Auth/
├── server/                     # Backend
│   ├── config/
│   │   └── environment.js      # Environment configuration manager
│   ├── middleware/
│   │   ├── authMiddleware.js   # JWT authentication
│   │   ├── csrf.js             # CSRF protection
│   │   ├── rateLimit.js        # Rate limiting
│   │   ├── rbac.js             # Role-based access control
│   │   └── validation.js       # Input validation
│   ├── models/
│   │   └── User.js             # Enhanced user model
│   ├── routes/
│   │   ├── authRoutes.js       # Authentication endpoints
│   │   ├── userRoutes.js       # User management endpoints
│   │   ├── adminRoutes.js      # Admin panel endpoints
│   │   └── mockOAuth.js        # Mock OAuth provider
│   ├── scripts/
│   │   └── seed.js             # Database seeding
│   ├── utils/
│   │   ├── jwt.js              # JWT utilities
│   │   ├── oauth.js            # OAuth utilities
│   │   ├── logger.js           # Logging service
│   │   └── tokenBlacklist.js   # Token blacklist
│   ├── index.js                # Express server
│   ├── package.json
│   └── .env
│
├── client/                     # Frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx      # Navigation with role-based display
│   │   │   └── ProtectedRoute.jsx
│   │   ├── context/
│   │   │   └── AuthContext.jsx # Auth state management
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx   # Login with OAuth
│   │   │   ├── SignupPage.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── SettingsPage.jsx # Profile & account linking
│   │   │   └── AdminPage.jsx   # Admin panel
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── .env
│
├── package.json                # Root scripts
└── README.md
```

## 🔌 API Endpoints

### Public Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/signup` | Create account |
| POST | `/auth/login` | Login with email/password |
| GET | `/auth/google` | Initiate Google OAuth |
| GET | `/auth/google/callback` | Google callback |
| GET | `/auth/facebook` | Initiate Facebook OAuth |
| GET | `/auth/facebook/callback` | Facebook callback |
| GET | `/health` | Health check |

### Protected Routes (Requires Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/me` | Get current user |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout |
| POST | `/auth/logout-all` | Logout from all devices |
| GET | `/api/users/profile` | Get user profile |
| PATCH | `/api/users/profile` | Update profile |
| PATCH | `/api/users/consents` | Update consents |
| GET | `/api/users/linked-providers` | Get linked providers |
| GET | `/api/users/link/:provider` | Link OAuth provider |
| DELETE | `/api/users/link/:provider` | Unlink provider |
| GET | `/api/users/audit-log` | Get user audit log |

### Admin Routes (Admin/Moderator Only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | List all users |
| GET | `/api/admin/users/:userId` | Get user details |
| PATCH | `/api/admin/users/:userId/role` | Update user role |
| PATCH | `/api/admin/users/:userId/status` | Activate/deactivate user |
| DELETE | `/api/admin/users/:userId` | Delete user |
| GET | `/api/admin/stats` | Get system statistics |
| GET | `/api/admin/audit-logs` | Get audit logs |
| GET | `/api/admin/security-events` | Get security events |

## 🔐 OAuth Setup

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project
3. Enable Google+ API
4. Create OAuth 2.0 Client ID
5. Add redirect URI: `http://localhost:5000/auth/google/callback`
6. Copy Client ID and Secret to `server/.env`
7. Set `MOCK_OAUTH=false`

### Facebook OAuth

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create new app (Consumer type)
3. Add Facebook Login product
4. Configure OAuth settings:
   - Valid OAuth Redirect URIs: `http://localhost:5000/auth/facebook/callback`
   - Data Deletion URL: `http://localhost:5000/auth/facebook/data-deletion`
5. Copy App ID and Secret to `server/.env`
6. Set `MOCK_OAUTH=false`

## 🔒 Security Features

### Rate Limiting

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| Auth (login/signup) | 5 requests | 15 minutes |
| OAuth initiation | 10 requests | 10 minutes |
| API (authenticated) | 100 requests | 15 minutes |
| Signup | 3 requests | 1 hour |

### Token Security

- **Access Token**: 15 minutes, httpOnly cookie, includes userId and role
- **Refresh Token**: 7 days, stored in database, httpOnly cookie
- **Blacklist**: Server-side invalidation on logout
- **Rotation**: Optional refresh token rotation

### Input Validation

- Email format validation
- Password strength (8+ characters)
- URL validation
- XSS sanitization
- Character limits per field
- MongoDB injection prevention

### CSRF Protection

- Single-use CSRF tokens
- State parameter for OAuth
- Session-based verification
- 60-minute token expiration

## 👥 Role-Based Access Control

### Roles

- **User**: Default role, access to own profile
- **Moderator**: Can view users and audit logs
- **Admin**: Full system access, user management

### Claims

- `read:users` - View user list
- `write:users` - Modify users
- `delete:users` - Delete users
- `read:audit` - View audit logs
- `write:settings` - Modify settings
- `manage:roles` - Assign roles

### UI Gating

```jsx
// Example: Show admin link only to admins/moderators
{(user.role === 'admin' || user.role === 'moderator') && (
  <Link to="/admin">Admin Panel</Link>
)}
```

## 📊 Audit Logging

Every action is logged with:
- Action type (login, logout, profile_update, etc.)
- User ID and email
- IP address
- User agent
- Correlation ID for tracing
- Timestamp
- Action details

View logs:
- **User**: `/api/users/audit-log` (own logs)
- **Admin**: `/api/admin/audit-logs` (all logs)

## 📝 Available Scripts

### Root Directory

```bash
npm run install-all  # Install all dependencies
npm run dev          # Start both servers
npm run server       # Start backend only
npm run client       # Start frontend only
```

### Server Directory

```bash
npm start            # Start server
npm run dev          # Start with nodemon
npm run seed         # Seed database with test users
npm run seed:clear   # Clear and reseed database
```

### Client Directory

```bash
npm run dev          # Start Vite dev server
npm run build        # Build for production
npm run preview      # Preview production build
```

## 🧪 Testing

### Using Mock OAuth (No Credentials Needed)

1. Set `MOCK_OAUTH=true` in `server/.env`
2. Click OAuth login buttons
3. Select a test user from the mock provider UI
4. Complete authentication

### Test Users (After Seeding)

Login to test different roles:

```
Admin:
  Email: admin@example.com
  Password: Admin123!

Moderator:
  Email: moderator@example.com
  Password: Moderator123!

User:
  Email: user@example.com
  Password: User123!
```

### Testing Checklist

- [ ] Email/password signup works
- [ ] Email/password login works
- [ ] OAuth login redirects correctly
- [ ] Profile update saves changes
- [ ] Account linking works
- [ ] Account unlinking prevents last method removal
- [ ] Admin can manage users
- [ ] Rate limiting blocks excessive requests
- [ ] Logout invalidates tokens
- [ ] Refresh token renews access

## 🚢 Production Deployment

### Pre-Deployment Checklist

- [ ] Generate strong JWT secrets (64 bytes)
- [ ] Set `NODE_ENV=production`
- [ ] Use MongoDB Atlas (not local)
- [ ] Update OAuth redirect URIs to production
- [ ] Add Facebook data deletion URL
- [ ] Enable HTTPS (secure cookies)
- [ ] Configure CORS for production domain
- [ ] Set up error logging (Sentry, etc.)
- [ ] Enable MongoDB backups
- [ ] Configure monitoring (Datadog, New Relic)
- [ ] Review rate limits for production load
- [ ] Security audit

### Environment Variables (Production)

```env
NODE_ENV=production
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/dbname
JWT_SECRET=<strong-64-byte-secret>
JWT_REFRESH_SECRET=<strong-64-byte-secret>
CLIENT_URL=https://yourdomain.com
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
FACEBOOK_CLIENT_ID=...
FACEBOOK_CLIENT_SECRET=...
FACEBOOK_REDIRECT_URI=https://yourdomain.com/auth/facebook/callback
```

### Deployment Platforms

- **Vercel** (Frontend + Backend)
- **AWS Elastic Beanstalk** (Backend) + S3 (Frontend)
- **Google Cloud Run** (Containers)
- **Heroku** (Easy deployment)
- **DigitalOcean App Platform**

### Database

- **MongoDB Atlas** (Recommended)
  - M10+ tier for production
  - Automated backups
  - Geographic distribution
  - Built-in monitoring

## 🐛 Troubleshooting

### MongoDB Connection Failed

```bash
# Check MongoDB is running
mongosh

# Or use MongoDB Atlas connection string
MONGODB_URI=mongodb+srv://...
```

### Port Already in Use

```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9

# Kill process on port 5173
lsof -ti:5173 | xargs kill -9
```

### OAuth Redirect URI Mismatch

- Ensure URIs match exactly (including http/https)
- No trailing slashes
- Check provider console and `.env` match

### CORS Errors

- Verify `CLIENT_URL` in server `.env`
- Check `withCredentials: true` in axios
- Clear browser cookies

### Can't Access Admin Panel

- Login with `admin@example.com` / `Admin123!` (after seeding)
- Check user role in database
- Verify `/admin` route is protected

## 💡 Development Tips

### Useful Endpoints

- **Health Check**: http://localhost:5000/health
- **Config Debug**: http://localhost:5000/config (dev only)
- **Mock OAuth**: http://localhost:5000/mock-oauth/select/google

### Quick Commands

```bash
# Regenerate JWT secrets
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Check MongoDB connection
mongosh mongodb://localhost:27017/oauth-social-login

# View server logs with correlation IDs
npm run dev | grep correlationId

# Reseed database
npm run seed:clear
```

## 📈 Features in Detail

### Account Linking

Users can link multiple OAuth providers to a single account:

1. Go to Settings page
2. Click "Connect" for Google or Facebook
3. Complete OAuth flow
4. Provider is linked to account
5. Can login with any linked provider

Safety features:
- Cannot unlink last authentication method
- Duplicate provider detection
- Confirmation required for unlinking

### Profile Sync

Control how OAuth providers update your profile:

- **Profile Sync**: Auto-update name/avatar from providers
- **Data Processing**: Required for core functionality
- **Marketing**: Optional email preferences

### Audit Logging

Every action is tracked:
- Account creation
- Logins and logouts
- Profile updates
- Provider linking/unlinking
- Role changes (admin actions)
- Failed login attempts

View your own audit log in Settings or view all logs in Admin Panel.

## 🎓 Learning Resources

This project demonstrates:

- OAuth2 Authorization Code Flow with PKCE
- JWT authentication with refresh tokens
- Role-based access control (RBAC)
- Claim-based permissions
- Security best practices
- Structured logging
- React Context API
- Protected routes
- MongoDB schema design
- RESTful API design
- Rate limiting algorithms
- Input validation
- CSRF protection
- Token blacklisting
