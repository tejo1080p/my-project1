const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');

// In-memory cache for avatar images
const avatarCache = new Map();
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Proxy endpoint for avatar images
 * This bypasses CORS and rate limiting issues by caching images server-side
 */
router.get('/proxy', async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({ error: 'URL parameter is required' });
    }

    // Validate URL is from allowed domains
    const allowedDomains = [
      'lh3.googleusercontent.com',
      'graph.facebook.com',
      'platform-lookaside.fbsbx.com',
      'via.placeholder.com',
      'avatars.githubusercontent.com',
      'cdn.discordapp.com'
    ];

    const urlObj = new URL(url);
    const isAllowed = allowedDomains.some(domain => urlObj.hostname.includes(domain));

    if (!isAllowed) {
      return res.status(403).json({ error: 'Domain not allowed' });
    }

    // Generate cache key
    const cacheKey = crypto.createHash('md5').update(url).digest('hex');

    // Check cache
    const cached = avatarCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
      res.set('Content-Type', cached.contentType);
      res.set('Cache-Control', 'public, max-age=86400'); // 24 hours
      res.set('X-Cache', 'HIT');
      return res.send(cached.data);
    }

    // Fetch image from source
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; OAuth-App/1.0)',
        'Accept': 'image/*'
      }
    });

    const contentType = response.headers['content-type'] || 'image/jpeg';
    const imageData = Buffer.from(response.data);

    // Cache the image
    avatarCache.set(cacheKey, {
      data: imageData,
      contentType,
      timestamp: Date.now()
    });

    // Clean up old cache entries (keep max 1000 images)
    if (avatarCache.size > 1000) {
      const keys = Array.from(avatarCache.keys());
      const oldestKeys = keys.slice(0, 100);
      oldestKeys.forEach(key => avatarCache.delete(key));
    }

    // Return image
    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-Cache', 'MISS');
    res.send(imageData);

  } catch (error) {
    console.error('Avatar proxy error:', error.message);

    // Return a default avatar on error
    const defaultSvg = `
      <svg width="96" height="96" xmlns="http://www.w3.org/2000/svg">
        <rect width="96" height="96" fill="#667eea"/>
        <text x="50%" y="50%" text-anchor="middle" dy=".35em" 
              font-size="40" font-weight="bold" fill="white" font-family="Arial">
          ?
        </text>
      </svg>
    `;

    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(defaultSvg);
  }
});

/**
 * Clear cache endpoint (admin only)
 */
router.post('/clear-cache', (req, res) => {
  const cleared = avatarCache.size;
  avatarCache.clear();
  res.json({ 
    message: 'Avatar cache cleared',
    itemsCleared: cleared 
  });
});

/**
 * Cache stats endpoint
 */
router.get('/cache-stats', (req, res) => {
  res.json({
    size: avatarCache.size,
    maxSize: 1000,
    cacheDuration: CACHE_DURATION,
    usage: `${((avatarCache.size / 1000) * 100).toFixed(1)}%`
  });
});

module.exports = router;

