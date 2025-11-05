import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const AdminPage = () => {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('users')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState({ type: '', text: '' })
  
  // Users state
  const [users, setUsers] = useState([])
  const [pagination, setPagination] = useState({})
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  
  // Stats state
  const [stats, setStats] = useState(null)

  // Audit logs state
  const [auditLogs, setAuditLogs] = useState([])

  useEffect(() => {
    // Check if user is admin
    if (user && user.role !== 'admin' && user.role !== 'moderator') {
      navigate('/dashboard')
    }
  }, [user, navigate])

  useEffect(() => {
    if (activeTab === 'users') {
      loadUsers()
    } else if (activeTab === 'stats') {
      loadStats()
    } else if (activeTab === 'audit') {
      loadAuditLogs()
    }
  }, [activeTab, search, roleFilter])

  const loadUsers = async (page = 1) => {
    setLoading(true)
    try {
      const params = { page, limit: 20 }
      if (search) params.search = search
      if (roleFilter) params.role = roleFilter

      const response = await axios.get('/api/admin/users', { params })
      setUsers(response.data.users)
      setPagination(response.data.pagination)
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to load users' 
      })
    } finally {
      setLoading(false)
    }
  }

  const loadStats = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/admin/stats')
      setStats(response.data)
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to load stats' 
      })
    } finally {
      setLoading(false)
    }
  }

  const loadAuditLogs = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/admin/audit-logs')
      setAuditLogs(response.data.logs)
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to load audit logs' 
      })
    } finally {
      setLoading(false)
    }
  }

  const handleRoleUpdate = async (userId, newRole) => {
    if (!confirm(`Are you sure you want to change this user's role to ${newRole}?`)) {
      return
    }

    try {
      await axios.patch(`/api/admin/users/${userId}/role`, { role: newRole })
      setMessage({ type: 'success', text: 'User role updated successfully!' })
      loadUsers(pagination.page)
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to update role' 
      })
    }
  }

  const handleStatusToggle = async (userId, currentStatus) => {
    const newStatus = !currentStatus
    const action = newStatus ? 'activate' : 'deactivate'
    
    if (!confirm(`Are you sure you want to ${action} this user?`)) {
      return
    }

    try {
      await axios.patch(`/api/admin/users/${userId}/status`, { isActive: newStatus })
      setMessage({ type: 'success', text: `User ${action}d successfully!` })
      loadUsers(pagination.page)
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to update status' 
      })
    }
  }

  const handleDeleteUser = async (userId) => {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
      return
    }

    try {
      await axios.delete(`/api/admin/users/${userId}`)
      setMessage({ type: 'success', text: 'User deleted successfully!' })
      loadUsers(pagination.page)
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to delete user' 
      })
    }
  }

  const formatDate = (date) => {
    return new Date(date).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return (
    <div className="admin-page">
      <div className="admin-container">
        <div className="admin-header">
          <h1>🛡️ Admin Panel</h1>
          <p>Manage users, view analytics, and monitor system activity</p>
        </div>

        {message.text && (
          <div className={`alert alert-${message.type}`}>
            {message.text}
          </div>
        )}

        <div className="admin-tabs">
          <button 
            className={activeTab === 'users' ? 'active' : ''}
            onClick={() => setActiveTab('users')}
          >
            👥 Users
          </button>
          <button 
            className={activeTab === 'stats' ? 'active' : ''}
            onClick={() => setActiveTab('stats')}
          >
            📊 Statistics
          </button>
          <button 
            className={activeTab === 'audit' ? 'active' : ''}
            onClick={() => setActiveTab('audit')}
          >
            📝 Audit Logs
          </button>
        </div>

        <div className="admin-content">
          {activeTab === 'users' && (
            <div>
              <div className="admin-filters">
                <input
                  type="text"
                  placeholder="Search users..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="search-input"
                />
                <select 
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  className="role-filter"
                >
                  <option value="">All Roles</option>
                  <option value="admin">Admin</option>
                  <option value="moderator">Moderator</option>
                  <option value="user">User</option>
                </select>
              </div>

              {loading ? (
                <div className="loading">Loading users...</div>
              ) : (
                <>
                  <div className="users-table">
                    <table>
                      <thead>
                        <tr>
                          <th>User</th>
                          <th>Role</th>
                          <th>Provider</th>
                          <th>Status</th>
                          <th>Joined</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.map(user => (
                          <tr key={user._id}>
                            <td>
                              <div className="user-cell">
                                {user.avatar ? (
                                  <img src={user.avatar} alt={user.name} className="user-avatar" />
                                ) : (
                                  <div className="user-avatar-placeholder">
                                    {user.name?.charAt(0).toUpperCase()}
                                  </div>
                                )}
                                <div>
                                  <div className="user-name">{user.name}</div>
                                  <div className="user-email">{user.email}</div>
                                </div>
                              </div>
                            </td>
                            <td>
                              <select
                                value={user.role}
                                onChange={(e) => handleRoleUpdate(user._id, e.target.value)}
                                className="role-select"
                              >
                                <option value="user">User</option>
                                <option value="moderator">Moderator</option>
                                <option value="admin">Admin</option>
                              </select>
                            </td>
                            <td>
                              <span className={`badge badge-${user.provider}`}>
                                {user.provider}
                              </span>
                            </td>
                            <td>
                              <span className={`status ${user.isActive ? 'active' : 'inactive'}`}>
                                {user.isActive ? 'Active' : 'Inactive'}
                              </span>
                            </td>
                            <td>{formatDate(user.createdAt)}</td>
                            <td>
                              <div className="action-buttons">
                                <button
                                  onClick={() => handleStatusToggle(user._id, user.isActive)}
                                  className="btn btn-sm btn-secondary"
                                  title={user.isActive ? 'Deactivate' : 'Activate'}
                                >
                                  {user.isActive ? '🔒' : '🔓'}
                                </button>
                                <button
                                  onClick={() => handleDeleteUser(user._id)}
                                  className="btn btn-sm btn-danger"
                                  title="Delete user"
                                >
                                  🗑️
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {pagination.pages > 1 && (
                    <div className="pagination">
                      <button
                        onClick={() => loadUsers(pagination.page - 1)}
                        disabled={pagination.page === 1}
                        className="btn btn-secondary"
                      >
                        Previous
                      </button>
                      <span>
                        Page {pagination.page} of {pagination.pages}
                      </span>
                      <button
                        onClick={() => loadUsers(pagination.page + 1)}
                        disabled={pagination.page === pagination.pages}
                        className="btn btn-secondary"
                      >
                        Next
                      </button>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {activeTab === 'stats' && stats && (
            <div>
              <div className="stats-grid">
                <div className="stat-card">
                  <h3>Total Users</h3>
                  <div className="stat-value">{stats.users.total}</div>
                </div>
                <div className="stat-card">
                  <h3>Active Users</h3>
                  <div className="stat-value">{stats.users.active}</div>
                </div>
                <div className="stat-card">
                  <h3>New This Month</h3>
                  <div className="stat-value">{stats.users.recent}</div>
                </div>
                <div className="stat-card">
                  <h3>Inactive Users</h3>
                  <div className="stat-value">{stats.users.inactive}</div>
                </div>
              </div>

              <div className="stats-charts">
                <div className="chart-card">
                  <h3>Users by Provider</h3>
                  <div className="chart-list">
                    {stats.byProvider.map(item => (
                      <div key={item._id} className="chart-item">
                        <span className="chart-label">{item._id}</span>
                        <div className="chart-bar">
                          <div 
                            className="chart-fill"
                            style={{ width: `${(item.count / stats.users.total) * 100}%` }}
                          ></div>
                        </div>
                        <span className="chart-value">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="chart-card">
                  <h3>Users by Role</h3>
                  <div className="chart-list">
                    {stats.byRole.map(item => (
                      <div key={item._id} className="chart-item">
                        <span className="chart-label">{item._id}</span>
                        <div className="chart-bar">
                          <div 
                            className="chart-fill"
                            style={{ width: `${(item.count / stats.users.total) * 100}%` }}
                          ></div>
                        </div>
                        <span className="chart-value">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'audit' && (
            <div>
              {loading ? (
                <div className="loading">Loading audit logs...</div>
              ) : (
                <div className="audit-logs">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>IP Address</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log, index) => (
                        <tr key={index}>
                          <td>{formatDate(log.timestamp)}</td>
                          <td>
                            <div>{log.name}</div>
                            <div className="user-email">{log.email}</div>
                          </td>
                          <td>
                            <span className="badge">{log.action}</span>
                          </td>
                          <td>{log.ip}</td>
                          <td>
                            {log.details && (
                              <code>{JSON.stringify(log.details)}</code>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AdminPage

