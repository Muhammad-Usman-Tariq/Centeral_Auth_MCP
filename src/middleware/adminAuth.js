const { verifyAdminToken } = require('../crypto/tokens');

function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({
      success: false,
      error: 'unauthorized',
      message: 'Authorization header required'
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({
      success: false,
      error: 'invalid_token',
      message: 'Format must be: Bearer <token>'
    });
  }

  try {
    const decoded = verifyAdminToken(parts[1]);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'invalid_token',
      message: 'Admin session expired or invalid'
    });
  }
}

module.exports = adminAuth;
