const express = require('express');
const axios = require('axios');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const NodeCache = require('node-cache');
const winston = require('winston');
const { promisify } = require('util');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Initialize cache with 5 minute TTL
const cache = new NodeCache({ stdTTL: 300 });

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Create rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(helmet()); // Security headers
app.use(compression()); // Compress responses
app.use(express.json({ limit: '10kb' })); // Limit payload size
app.use(limiter);
app.use(express.static(path.join(__dirname, 'public')));

// Store active sharing sessions with improved structure
class SessionManager {
  constructor() {
    this.sessions = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000); // Cleanup every minute
  }

  addSession(id, data) {
    this.sessions.set(id, {
      ...data,
      startTime: Date.now(),
      lastUpdate: Date.now(),
      status: 'active'
    });
  }

  updateSession(id, updates) {
    const session = this.sessions.get(id);
    if (session) {
      this.sessions.set(id, {
        ...session,
        ...updates,
        lastUpdate: Date.now()
      });
    }
  }

  cleanup() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now - session.lastUpdate > 3600000) { // 1 hour
        this.sessions.delete(id);
      }
    }
  }

  getAllSessions() {
    return Array.from(this.sessions.entries()).map(([id, session]) => ({
      id,
      ...session
    }));
  }
}

const sessionManager = new SessionManager();

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  logger.error('Error:', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  res.status(err.status || 500).json({
    status: 'error',
    message: err.message || 'Internal server error'
  });
};

// Routes with async/await and better error handling
app.get('/api/sessions', async (req, res) => {
  try {
    const sessions = sessionManager.getAllSessions();
    res.json({
      status: 'success',
      data: sessions
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/share', async (req, res, next) => {
  const { cookie, url, amount, interval } = req.body;

  try {
    // Validate input
    if (!cookie || !url || !amount || !interval) {
      throw Object.assign(new Error('Missing required parameters'), { status: 400 });
    }

    if (amount > 1000) {
      throw Object.assign(new Error('Amount exceeds maximum limit'), { status: 400 });
    }

    // Check cache for postID
    const cachedId = cache.get(url);
    const postId = cachedId || await getPostID(url);
    
    if (!cachedId && postId) {
      cache.set(url, postId);
    }

    if (!postId) {
      throw Object.assign(new Error('Invalid URL or post not accessible'), { status: 400 });
    }

    const sessionId = `${postId}-${Date.now()}`;
    const cookies = await convertCookie(cookie);
    const accessToken = await getAccessToken(cookies);

    if (!accessToken) {
      throw Object.assign(new Error('Failed to obtain access token'), { status: 401 });
    }

    // Start sharing process
    await startSharing(sessionId, {
      cookies,
      accessToken,
      url,
      postId,
      amount: parseInt(amount),
      interval: parseInt(interval)
    });

    res.json({
      status: 'success',
      data: {
        sessionId,
        message: 'Sharing process started successfully'
      }
    });
  } catch (error) {
    next(error);
  }
});

// Enhanced sharing function with better error handling and retry logic
async function startSharing(sessionId, config) {
  const { cookies, accessToken, url, postId, amount, interval } = config;
  
  sessionManager.addSession(sessionId, {
    url,
    postId,
    target: amount,
    count: 0,
    failures: 0
  });

  const headers = {
    'accept': '*/*',
    'accept-encoding': 'gzip, deflate',
    'connection': 'keep-alive',
    'cookie': cookies,
    'host': 'graph.facebook.com'
  };

  const share = async () => {
    try {
      const response = await axios.post(
        `https://graph.facebook.com/me/feed?link=https://m.facebook.com/${postId}&published=0&access_token=${accessToken}`,
        {},
        { 
          headers,
          timeout: 10000 // 10 second timeout
        }
      );

      if (response.status === 200) {
        sessionManager.updateSession(sessionId, {
          count: (sessionManager.sessions.get(sessionId)?.count || 0) + 1,
          lastSuccess: Date.now()
        });
      }
    } catch (error) {
      logger.error('Share failed:', {
        sessionId,
        error: error.message,
        postId
      });

      sessionManager.updateSession(sessionId, {
        failures: (sessionManager.sessions.get(sessionId)?.failures || 0) + 1,
        lastError: error.message
      });

      // Implement exponential backoff
      await new Promise(resolve => setTimeout(resolve, Math.min(1000 * Math.pow(2, failures), 30000)));
    }
  };

  // Improved sharing loop with batch processing
  const batchSize = 5;
  const delay = promisify(setTimeout);

  for (let i = 0; i < amount; i += batchSize) {
    const batch = Math.min(batchSize, amount - i);
    const promises = Array(batch).fill().map(() => share());
    
    await Promise.allSettled(promises);
    await delay(interval * 1000);

    const session = sessionManager.sessions.get(sessionId);
    if (session.failures > amount * 0.3) { // If more than 30% failed
      logger.error('Too many failures, stopping session:', { sessionId });
      sessionManager.updateSession(sessionId, { status: 'failed' });
      break;
    }
  }

  sessionManager.updateSession(sessionId, { status: 'completed' });
}

// Enhanced helper functions with caching and better error handling
async function getPostID(url) {
  try {
    const response = await axios.post('https://id.traodoisub.com/api.php',
      `link=${encodeURIComponent(url)}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 5000
      }
    );
    return response.data.id;
  } catch (error) {
    logger.error('Failed to get post ID:', {
      url,
      error: error.message
    });
    return null;
  }
}

async function getAccessToken(cookie) {
  try {
    const response = await axios.get('https://business.facebook.com/content_management', {
      headers: {
        'authority': 'business.facebook.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'cookie': cookie,
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'upgrade-insecure-requests': '1',
      },
      timeout: 5000
    });
    
    const token = response.data.match(/"accessToken":\s*"([^"]+)"/);
    return token?.[1];
  } catch (error) {
    logger.error('Failed to get access token:', error.message);
    return null;
  }
}

async function convertCookie(cookie) {
  try {
    const cookies = JSON.parse(cookie);
    const sbCookie = cookies.find(cookie => cookie.key === "sb");
    
    if (!sbCookie) {
      throw new Error("Invalid appstate: missing sb cookie");
    }

    return `sb=${sbCookie.value}; ${cookies
      .slice(1)
      .map(cookie => `${cookie.key}=${cookie.value}`)
      .join('; ')}`;
  } catch (error) {
    throw new Error("Invalid appstate format");
  }
}

// Error handling middleware should be last
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    logger.info('Process terminated');
  });
});

const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
