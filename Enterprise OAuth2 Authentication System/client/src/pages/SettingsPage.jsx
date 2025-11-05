import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { useSearchParams } from 'react-router-dom'
import axios from 'axios'

const SettingsPage = () => {
  const { user, checkAuth } = useAuth()
  const [searchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState('profile')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState({ type: '', text: '' })
  
  // Profile state
  const [profile, setProfile] = useState({
    name: '',
    bio: '',
    location: '',
    website: ''
  })

  // Consent state
  const [consents, setConsents] = useState({
    profileSync: true,
    dataProcessing: true,
    marketing: false
  })

  // Linked providers state
  const [linkedProviders, setLinkedProviders] = useState([])

  useEffect(() => {
    // Check for success/error messages from OAuth linking
    const success = searchParams.get('success')
    const error = searchParams.get('error')
    const provider = searchParams.get('provider')

    if (success === 'provider_linked' && provider) {
      setMessage({ 
        type: 'success', 
        text: `${provider.charAt(0).toUpperCase() + provider.slice(1)} account linked successfully!` 
      })
      loadLinkedProviders()
    } else if (error) {
      setMessage({ 
        type: 'error', 
        text: error.replace(/_/g, ' ') 
      })
    }

    // Clear URL params
    if (success || error) {
      window.history.replaceState({}, '', '/settings')
      setTimeout(() => setMessage({ type: '', text: '' }), 5000)
    }
  }, [searchParams])

  useEffect(() => {
    if (user) {
      setProfile({
        name: user.name || '',
        bio: user.bio || '',
        location: user.location || '',
        website: user.website || ''
      })
      setConsents({
        profileSync: user.consents?.profileSync ?? true,
        dataProcessing: user.consents?.dataProcessing ?? true,
        marketing: user.consents?.marketing ?? false
      })
      loadLinkedProviders()
    }
  }, [user])

  const loadLinkedProviders = async () => {
    try {
      const response = await axios.get('/api/users/linked-providers')
      setLinkedProviders(response.data.linked || [])
    } catch (error) {
      console.error('Failed to load linked providers:', error)
    }
  }

  const handleProfileUpdate = async (e) => {
    e.preventDefault()
    setLoading(true)
    setMessage({ type: '', text: '' })

    try {
      await axios.patch('/api/users/profile', profile)
      await checkAuth()
      setMessage({ type: 'success', text: 'Profile updated successfully!' })
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to update profile' 
      })
    } finally {
      setLoading(false)
    }
  }

  const handleConsentUpdate = async () => {
    setLoading(true)
    setMessage({ type: '', text: '' })

    try {
      await axios.patch('/api/users/consents', consents)
      await checkAuth()
      setMessage({ type: 'success', text: 'Preferences updated successfully!' })
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to update preferences' 
      })
    } finally {
      setLoading(false)
    }
  }

  const handleLinkProvider = async (provider) => {
    try {
      const response = await axios.get(`/api/users/link/${provider}`)
      if (response.data.authUrl) {
        window.location.href = response.data.authUrl
      }
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to initiate provider linking' 
      })
    }
  }

  const handleUnlinkProvider = async (provider) => {
    if (!confirm(`Are you sure you want to unlink your ${provider} account?`)) {
      return
    }

    setLoading(true)
    setMessage({ type: '', text: '' })

    try {
      await axios.delete(`/api/users/link/${provider}`)
      await loadLinkedProviders()
      await checkAuth()
      setMessage({ 
        type: 'success', 
        text: `${provider.charAt(0).toUpperCase() + provider.slice(1)} account unlinked successfully!` 
      })
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to unlink provider' 
      })
    } finally {
      setLoading(false)
    }
  }

  const isProviderLinked = (provider) => {
    return linkedProviders.some(p => p.provider === provider) || user?.provider === provider
  }

  return (
    <div className="settings-page">
      <div className="settings-container">
        <h1>Settings</h1>

        {message.text && (
          <div className={`alert alert-${message.type}`}>
            {message.text}
          </div>
        )}

        <div className="settings-tabs">
          <button 
            className={activeTab === 'profile' ? 'active' : ''}
            onClick={() => setActiveTab('profile')}
          >
            Profile
          </button>
          <button 
            className={activeTab === 'accounts' ? 'active' : ''}
            onClick={() => setActiveTab('accounts')}
          >
            Connected Accounts
          </button>
          <button 
            className={activeTab === 'privacy' ? 'active' : ''}
            onClick={() => setActiveTab('privacy')}
          >
            Privacy
          </button>
        </div>

        <div className="settings-content">
          {activeTab === 'profile' && (
            <div className="settings-section">
              <h2>Profile Information</h2>
              <form onSubmit={handleProfileUpdate}>
                <div className="form-group">
                  <label htmlFor="name">Name</label>
                  <input
                    type="text"
                    id="name"
                    value={profile.name}
                    onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="bio">Bio</label>
                  <textarea
                    id="bio"
                    value={profile.bio}
                    onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
                    rows="4"
                    maxLength="500"
                  />
                  <small>{profile.bio.length}/500 characters</small>
                </div>

                <div className="form-group">
                  <label htmlFor="location">Location</label>
                  <input
                    type="text"
                    id="location"
                    value={profile.location}
                    onChange={(e) => setProfile({ ...profile, location: e.target.value })}
                    maxLength="100"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="website">Website</label>
                  <input
                    type="url"
                    id="website"
                    value={profile.website}
                    onChange={(e) => setProfile({ ...profile, website: e.target.value })}
                    placeholder="https://example.com"
                  />
                </div>

                <button 
                  type="submit" 
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Saving...' : 'Save Changes'}
                </button>
              </form>
            </div>
          )}

          {activeTab === 'accounts' && (
            <div className="settings-section">
              <h2>Connected Accounts</h2>
              <p className="section-description">
                Link multiple authentication providers to your account for easier sign-in.
              </p>

              <div className="connected-accounts">
                {/* Google */}
                <div className="account-card">
                  <div className="account-info">
                    <div className="account-icon google">G</div>
                    <div>
                      <h3>Google</h3>
                      <p>
                        {isProviderLinked('google') 
                          ? 'Connected' 
                          : 'Not connected'}
                      </p>
                    </div>
                  </div>
                  {isProviderLinked('google') ? (
                    <button 
                      className="btn btn-danger"
                      onClick={() => handleUnlinkProvider('google')}
                      disabled={loading}
                    >
                      Unlink
                    </button>
                  ) : (
                    <button 
                      className="btn btn-primary"
                      onClick={() => handleLinkProvider('google')}
                      disabled={loading}
                    >
                      Connect
                    </button>
                  )}
                </div>

                {/* Facebook */}
                <div className="account-card">
                  <div className="account-info">
                    <div className="account-icon facebook">f</div>
                    <div>
                      <h3>Facebook</h3>
                      <p>
                        {isProviderLinked('facebook') 
                          ? 'Connected' 
                          : 'Not connected'}
                      </p>
                    </div>
                  </div>
                  {isProviderLinked('facebook') ? (
                    <button 
                      className="btn btn-danger"
                      onClick={() => handleUnlinkProvider('facebook')}
                      disabled={loading}
                    >
                      Unlink
                    </button>
                  ) : (
                    <button 
                      className="btn btn-primary"
                      onClick={() => handleLinkProvider('facebook')}
                      disabled={loading}
                    >
                      Connect
                    </button>
                  )}
                </div>

                {/* Email/Password */}
                <div className="account-card">
                  <div className="account-info">
                    <div className="account-icon local">📧</div>
                    <div>
                      <h3>Email & Password</h3>
                      <p>{user?.email}</p>
                    </div>
                  </div>
                  <span className="badge">Primary</span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'privacy' && (
            <div className="settings-section">
              <h2>Privacy & Data</h2>
              <p className="section-description">
                Manage how we use your data and what information we sync from connected accounts.
              </p>

              <div className="consent-options">
                <div className="consent-item">
                  <div>
                    <h3>Profile Sync</h3>
                    <p>Automatically update your profile with information from connected accounts</p>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={consents.profileSync}
                      onChange={(e) => setConsents({ ...consents, profileSync: e.target.checked })}
                    />
                    <span className="slider"></span>
                  </label>
                </div>

                <div className="consent-item">
                  <div>
                    <h3>Data Processing</h3>
                    <p>Allow us to process your data to improve your experience (Required)</p>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={consents.dataProcessing}
                      onChange={(e) => setConsents({ ...consents, dataProcessing: e.target.checked })}
                      disabled
                    />
                    <span className="slider"></span>
                  </label>
                </div>

                <div className="consent-item">
                  <div>
                    <h3>Marketing Communications</h3>
                    <p>Receive updates about new features and promotions</p>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={consents.marketing}
                      onChange={(e) => setConsents({ ...consents, marketing: e.target.checked })}
                    />
                    <span className="slider"></span>
                  </label>
                </div>
              </div>

              <button 
                className="btn btn-primary"
                onClick={handleConsentUpdate}
                disabled={loading}
              >
                {loading ? 'Saving...' : 'Save Preferences'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default SettingsPage

