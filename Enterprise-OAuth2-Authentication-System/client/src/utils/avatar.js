/**
 * Avatar utility functions
 * Handles avatar URLs with proxy support to avoid rate limiting
 */

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

/**
 * Get avatar URL with proxy support
 * @param {string} avatarUrl - Original avatar URL from OAuth provider
 * @param {boolean} useProxy - Whether to use proxy (default: true for Google URLs)
 * @returns {string} - Proxied or original URL
 */
export const getAvatarUrl = (avatarUrl, useProxy = null) => {
  if (!avatarUrl) return null;

  // Auto-detect if proxy is needed
  const needsProxy = useProxy !== null 
    ? useProxy 
    : avatarUrl.includes('googleusercontent.com') || 
      avatarUrl.includes('fbsbx.com');

  if (needsProxy) {
    return `${API_URL}/api/avatar/proxy?url=${encodeURIComponent(avatarUrl)}`;
  }

  return avatarUrl;
};

/**
 * Get initials from name for fallback avatar
 * @param {string} name - User's name
 * @returns {string} - Initials (max 2 chars)
 */
export const getInitials = (name) => {
  if (!name) return '?';
  
  const parts = name.trim().split(/\s+/);
  if (parts.length === 1) {
    return parts[0].charAt(0).toUpperCase();
  }
  
  return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
};

/**
 * Get color for avatar based on name
 * @param {string} name - User's name
 * @returns {string} - Gradient CSS
 */
export const getAvatarColor = (name) => {
  const colors = [
    'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
    'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
    'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
    'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
    'linear-gradient(135deg, #30cfd0 0%, #330867 100%)',
    'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)',
    'linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)'
  ];

  // Generate consistent color based on name
  const hash = name.split('').reduce((acc, char) => {
    return char.charCodeAt(0) + ((acc << 5) - acc);
  }, 0);

  return colors[Math.abs(hash) % colors.length];
};

/**
 * Preload avatar image
 * @param {string} url - Avatar URL
 * @returns {Promise} - Resolves when image is loaded
 */
export const preloadAvatar = (url) => {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(url);
    img.onerror = reject;
    img.src = url;
  });
};

