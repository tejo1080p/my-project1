import { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'

const AuthContext = createContext(null)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Configure axios defaults
  axios.defaults.baseURL = import.meta.env.VITE_API_URL || 'http://localhost:5000'
  axios.defaults.withCredentials = true

  // Check if user is logged in on mount
  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      const response = await axios.get('/auth/me')
      setUser(response.data.user)
    } catch (err) {
      setUser(null)
    } finally {
      setLoading(false)
    }
  }

  const login = async (email, password) => {
    try {
      setError(null)
      const response = await axios.post('/auth/login', { email, password })
      setUser(response.data.user)
      return { success: true }
    } catch (err) {
      const errorMessage = err.response?.data?.error || 'Login failed'
      setError(errorMessage)
      return { success: false, error: errorMessage }
    }
  }

  const signup = async (name, email, password) => {
    try {
      setError(null)
      const response = await axios.post('/auth/signup', { name, email, password })
      setUser(response.data.user)
      return { success: true }
    } catch (err) {
      const errorMessage = err.response?.data?.error || 'Signup failed'
      setError(errorMessage)
      return { success: false, error: errorMessage }
    }
  }

  const logout = async () => {
    try {
      await axios.post('/auth/logout')
      setUser(null)
    } catch (err) {
      console.error('Logout error:', err)
    }
  }

  const value = {
    user,
    loading,
    error,
    login,
    signup,
    logout,
    checkAuth
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

