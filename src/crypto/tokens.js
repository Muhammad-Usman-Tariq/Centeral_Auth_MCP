const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');
const { getPrivateKey, getPublicKey, getKeyId } = require('./keys');

/**
 * Signs an RS256 JWT for an MCP Client.
 * 
 * Works identically for:
 * - Mode 1 (OAuth 2.1 authorization_code and client_credentials)
 * - Mode 2 (Static long-lived API tokens)
 */
function signMcpToken({
  clientId,
  audience,
  mode = 'oauth2',
  expiresInSeconds = config.accessTokenExpiry,
  customClaims = {}
}) {
  const privateKey = getPrivateKey();
  const kid = getKeyId();
  const jti = crypto.randomUUID();

  const payload = {
    iss: config.issuerUrl,
    sub: clientId,
    client_id: clientId,
    aud: audience,
    auth_mode: mode,
    jti,
    ...customClaims
  };

  const token = jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    keyid: kid,
    expiresIn: expiresInSeconds
  });

  return {
    token,
    jti,
    expiresIn: expiresInSeconds,
    tokenType: 'Bearer'
  };
}

/**
 * Signs a static long-lived token (Mode 2)
 */
function signStaticToken({ clientId, audience, days = config.staticTokenExpiryDays }) {
  const expiresInSeconds = days * 24 * 60 * 60;
  return signMcpToken({
    clientId,
    audience,
    mode: 'static_token',
    expiresInSeconds,
    customClaims: {
      token_type_hint: 'static_long_lived'
    }
  });
}

/**
 * Verifies an RS256 token using the public key.
 */
function verifyMcpToken(token, expectedAudience = null) {
  const publicKey = getPublicKey();
  const options = {
    algorithms: ['RS256'],
    issuer: config.issuerUrl
  };
  if (expectedAudience) {
    options.audience = expectedAudience;
  }

  return jwt.verify(token, publicKey, options);
}

/**
 * Signs an Admin Session JWT.
 */
function signAdminToken(username) {
  return jwt.sign(
    { sub: username, role: 'admin' },
    config.adminJwtSecret,
    { expiresIn: '12h' }
  );
}

/**
 * Verifies an Admin Session JWT.
 */
function verifyAdminToken(token) {
  return jwt.verify(token, config.adminJwtSecret);
}

/**
 * Verifies OAuth 2.1 PKCE S256 Challenge.
 * RFC 7636: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
 */
function verifyPkceChallenge(codeVerifier, codeChallenge, method = 'S256') {
  if (method !== 'S256') {
    // OAuth 2.1 mandates S256. 'plain' is disallowed.
    return false;
  }
  if (!codeVerifier || !codeChallenge) {
    return false;
  }

  const computedHash = crypto
    .createHash('sha256')
    .update(codeVerifier, 'ascii')
    .digest('base64url');

  return crypto.timingSafeEqual(
    Buffer.from(computedHash, 'utf8'),
    Buffer.from(codeChallenge, 'utf8')
  );
}

/**
 * Generates secure random identifiers and secrets.
 */
function generateClientId(name = '') {
  const sanitized = name.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').substring(0, 16);
  const rand = crypto.randomBytes(8).toString('hex');
  return sanitized ? `mcp_${sanitized}_${rand}` : `mcp_${rand}`;
}

function generateClientSecret() {
  return `mcp_sec_${crypto.randomBytes(32).toString('base64url')}`;
}

function generateAuthCode() {
  return `ac_${crypto.randomBytes(24).toString('base64url')}`;
}

async function hashSecret(secret) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(secret, salt);
}

async function verifySecret(secret, hash) {
  if (!secret || !hash) return false;
  return bcrypt.compare(secret, hash);
}

module.exports = {
  signMcpToken,
  signStaticToken,
  verifyMcpToken,
  signAdminToken,
  verifyAdminToken,
  verifyPkceChallenge,
  generateClientId,
  generateClientSecret,
  generateAuthCode,
  hashSecret,
  verifySecret
};
