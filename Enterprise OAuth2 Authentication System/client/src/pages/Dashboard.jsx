import { useAuth } from '../context/AuthContext'
import Avatar from '../components/Avatar'

const Dashboard = () => {
  const { user } = useAuth()

  const getProviderBadge = (provider) => {
    const badges = {
      google: { color: '#4285F4', icon: 'G', label: 'Google' },
      facebook: { color: '#1877F2', icon: 'f', label: 'Facebook' },
      local: { color: '#6366F1', icon: '📧', label: 'Email' }
    }
    return badges[provider] || badges.local
  }

  const badge = getProviderBadge(user?.provider)

  return (
    <div className="dashboard-page">
      <div className="dashboard-container">
        <div className="dashboard-card">
          <div className="dashboard-header">
            <h1>Welcome to Your Dashboard</h1>
            <p>You're successfully logged in!</p>
          </div>

          <div className="profile-section">
            <div className="profile-avatar-large">
              <Avatar user={user} size="xlarge" />
            </div>

            <div className="profile-info">
              <h2>{user?.name}</h2>
              <p className="email">{user?.email}</p>
              
              <div className="provider-badge" style={{ backgroundColor: badge.color }}>
                <span className="badge-icon">{badge.icon}</span>
                <span className="badge-label">Logged in with {badge.label}</span>
              </div>
            </div>
          </div>

          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon">👤</div>
              <div className="stat-content">
                <h3>Account Type</h3>
                <p>{user?.provider === 'local' ? 'Email/Password' : `${badge.label} OAuth`}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">📅</div>
              <div className="stat-content">
                <h3>Member Since</h3>
                <p>{new Date(user?.createdAt).toLocaleDateString('en-US', { 
                  year: 'numeric', 
                  month: 'long', 
                  day: 'numeric' 
                })}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">🕒</div>
              <div className="stat-content">
                <h3>Last Login</h3>
                <p>{new Date(user?.lastLogin).toLocaleString('en-US', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit'
                })}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">🔐</div>
              <div className="stat-content">
                <h3>Security</h3>
                <p>JWT Token Active</p>
              </div>
            </div>
          </div>

          <div className="info-section">
            <h3>🎉 Authentication Successful!</h3>
            <div className="info-box">
              <p>
                Your account is secured with JWT tokens stored in httpOnly cookies.
                This implementation uses OAuth2 Authorization Code Flow with PKCE for enhanced security.
              </p>
              <ul className="feature-list">
                <li>✅ Secure JWT-based authentication</li>
                <li>✅ OAuth2 with PKCE (Google & Facebook)</li>
                <li>✅ HttpOnly cookies for token storage</li>
                <li>✅ CSRF protection with state parameter</li>
                <li>✅ Refresh token rotation</li>
                <li>✅ MongoDB data persistence</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard

