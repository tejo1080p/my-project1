import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Avatar from './Avatar'

const Navbar = () => {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <Link to="/" className="navbar-logo">
          <span className="logo-icon">🔐</span>
          OAuth Login
        </Link>
        
        <div className="navbar-menu">
          {user ? (
            <>
              <Link to="/dashboard" className="navbar-link">
                Dashboard
              </Link>
              <Link to="/settings" className="navbar-link">
                Settings
              </Link>
              {(user.role === 'admin' || user.role === 'moderator') && (
                <Link to="/admin" className="navbar-link admin-link">
                  🛡️ Admin
                </Link>
              )}
              <div className="user-info">
                <Avatar user={user} size="small" />
                <span className="user-name">{user.name}</span>
                {user.role === 'admin' && <span className="role-badge admin">Admin</span>}
                {user.role === 'moderator' && <span className="role-badge moderator">Mod</span>}
              </div>
              <button onClick={handleLogout} className="btn btn-outline">
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="btn btn-outline">
                Login
              </Link>
              <Link to="/signup" className="btn btn-primary">
                Sign Up
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  )
}

export default Navbar

