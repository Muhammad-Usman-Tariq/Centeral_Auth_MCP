const app = require('./app');
const config = require('./config');
const { initDatabase } = require('./db/database');
const { initKeys } = require('./crypto/keys');

// Initialize Database & Crypto Keys
console.log('--- Central Auth Server for MCP ---');
initDatabase();
initKeys();

const server = app.listen(config.port, () => {
  console.log(`[Server] Running on port ${config.port}`);
  console.log(`[Server] Issuer URL: ${config.issuerUrl}`);
  console.log(`[Server] Discovery: ${config.issuerUrl}/.well-known/oauth-authorization-server`);
  console.log(`[Server] JWKS:      ${config.issuerUrl}/.well-known/jwks.json`);
  console.log(`[Server] Admin UI:  ${config.issuerUrl}/admin`);
  console.log('-----------------------------------');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('[Server] SIGINT received. Shutting down gracefully...');
  server.close(() => {
    process.exit(0);
  });
});

module.exports = server;
