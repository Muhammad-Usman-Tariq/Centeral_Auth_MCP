const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

module.exports = {
  port: parseInt(process.env.PORT || '3000', 10),
  issuerUrl: (process.env.ISSUER_URL || 'http://localhost:3000').replace(/\/+$/, ''),
  nodeEnv: process.env.NODE_ENV || 'development',
  requireHttps: process.env.REQUIRE_HTTPS === 'true',

  dbPath: path.resolve(process.env.DB_PATH || './data/auth.db'),
  keysDir: path.resolve(process.env.KEYS_DIR || './.keys'),
  privateKeyPem: process.env.PRIVATE_KEY_PEM,
  publicKeyPem: process.env.PUBLIC_KEY_PEM,

  adminUsername: process.env.ADMIN_USERNAME || 'admin',
  adminPassword: process.env.ADMIN_PASSWORD || 'admin-mcp-secret-2026',
  adminJwtSecret: process.env.ADMIN_JWT_SECRET || 'central-mcp-admin-jwt-secret-session-key',

  accessTokenExpiry: parseInt(process.env.ACCESS_TOKEN_EXPIRY || '3600', 10), // in seconds
  staticTokenExpiryDays: parseInt(process.env.STATIC_TOKEN_EXPIRY_DAYS || '90', 10),
  authCodeExpirySeconds: parseInt(process.env.AUTH_CODE_EXPIRY_SECONDS || '300', 10),

  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '300', 10)
};
