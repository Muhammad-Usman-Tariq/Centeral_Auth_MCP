const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const { httpsEnforcer, errorHandler } = require('./middleware/errorHandler');

const wellKnownRoutes = require('./routes/wellKnown');
const oauthRoutes = require('./routes/oauth');
const adminRoutes = require('./routes/admin');

const app = express();

// Trust reverse proxy (standard for VPS deployments behind Nginx, Caddy, or Cloudflare)
app.set('trust proxy', 1);

// Security Headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"]
      }
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })
);

// HTTPS Enforcement (when configured in production)
app.use(httpsEnforcer);

// Body Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve Admin Frontend Dashboard
const adminPublicDir = path.join(__dirname, '../public/admin');
app.use('/admin', express.static(adminPublicDir));

// Route Mounts
app.use('/.well-known', wellKnownRoutes);
app.use('/', oauthRoutes);
app.use('/admin', adminRoutes);

// Root redirect to /admin
app.get('/', (req, res) => {
  res.redirect('/admin');
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Centralized Error Handler
app.use(errorHandler);

module.exports = app;
