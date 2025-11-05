import { useState } from 'react';
import { getAvatarUrl, getInitials, getAvatarColor } from '../utils/avatar';

/**
 * Avatar component with automatic fallback
 * Handles image loading errors gracefully
 */
const Avatar = ({ 
  user, 
  size = 'medium', 
  className = '',
  useProxy = true 
}) => {
  const [imageError, setImageError] = useState(false);

  const sizeClasses = {
    small: 'avatar-small',
    medium: 'avatar-medium',
    large: 'avatar-large',
    xlarge: 'avatar-xlarge'
  };

  const sizeStyles = {
    small: { width: '32px', height: '32px', fontSize: '14px' },
    medium: { width: '48px', height: '48px', fontSize: '18px' },
    large: { width: '96px', height: '96px', fontSize: '36px' },
    xlarge: { width: '128px', height: '128px', fontSize: '48px' }
  };

  const avatarUrl = user?.avatar ? getAvatarUrl(user.avatar, useProxy) : null;
  const showImage = avatarUrl && !imageError;
  const initials = getInitials(user?.name);
  const bgColor = getAvatarColor(user?.name || 'User');

  const containerStyle = {
    ...sizeStyles[size],
    borderRadius: '50%',
    overflow: 'hidden',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: showImage ? 'transparent' : bgColor,
    color: 'white',
    fontWeight: 'bold',
    flexShrink: 0
  };

  return (
    <div 
      className={`avatar ${sizeClasses[size]} ${className}`}
      style={containerStyle}
      title={user?.name}
    >
      {showImage ? (
        <img
          src={avatarUrl}
          alt={user.name}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover'
          }}
          onError={() => setImageError(true)}
        />
      ) : (
        <span>{initials}</span>
      )}
    </div>
  );
};

export default Avatar;

