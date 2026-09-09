const config = require('../config');

function httpsEnforcer(req, res, next) {
  if (!config.requireHttps) {
    return next();
  }

  // Check standard x-forwarded-proto or TLS connection
  const proto = req.headers['x-forwarded-proto'] || (req.connection.encrypted ? 'https' : 'http');
  if (proto !== 'https') {
    if (req.method === 'GET' || req.method === 'HEAD') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    return res.status(403).json({
      error: 'https_required',
      error_description: 'HTTPS connection is strictly required for this endpoint.'
    });
  }

  next();
}

function errorHandler(err, req, res, next) {
  console.error('[Error]', err);

  // If error happened on OAuth endpoints, return standard RFC 6749 JSON
  if (req.path.startsWith('/token') || req.path.startsWith('/authorize') || req.path.startsWith('/register')) {
    const status = err.status || 400;
    return res.status(status).json({
      error: err.code || 'invalid_request',
      error_description: err.message || 'An error occurred during authentication processing'
    });
  }

  res.status(err.status || 500).json({
    success: false,
    error: err.code || 'server_error',
    message: err.message || 'Internal server error'
  });
}

module.exports = {
  httpsEnforcer,
  errorHandler
};
