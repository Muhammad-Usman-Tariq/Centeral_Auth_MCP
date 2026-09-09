const express = require('express');
const router = express.Router();
const cors = require('cors');
const models = require('../db/models');
const clientService = require('../services/clientService');
const oauthService = require('../services/oauthService');
const { tokenLimiter, registerLimiter, authLimiter } = require('../middleware/rateLimiter');

// Token and OAuth endpoints allow CORS for seamless client calls
router.use(cors({ origin: '*' }));

/**
 * RFC 7591 Dynamic Client Registration
 * Allows compliant LLM clients (e.g. Claude Desktop, Cursor, agents) to self-register
 */
router.post('/register', registerLimiter, async (req, res) => {
  try {
    const {
      client_name,
      name,
      redirect_uris = [],
      audience = null
    } = req.body;

    const mcpName = client_name || name;
    if (!mcpName) {
      return res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: 'client_name is required'
      });
    }

    const clientAudience = audience || `mcp-${mcpName.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;

    const { client, clientSecret } = await clientService.registerClient({
      name: mcpName,
      audience: clientAudience,
      allowedRedirectUris: Array.isArray(redirect_uris) ? redirect_uris : [redirect_uris],
      clientType: 'confidential',
      ipAddress: req.ip
    });

    res.status(201).json({
      client_id: client.client_id,
      client_secret: clientSecret,
      client_name: client.name,
      audience: client.audience,
      redirect_uris: client.allowed_redirect_uris,
      grant_types: ['authorization_code', 'client_credentials'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post'
    });
  } catch (err) {
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: err.message
    });
  }
});

/**
 * OAuth 2.1 /authorize endpoint
 * Mandates PKCE with S256
 */
router.get('/authorize', authLimiter, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = 'mcp:all',
    state = '',
    code_challenge,
    code_challenge_method
  } = req.query;

  // 1. Validate response_type
  if (response_type !== 'code') {
    return res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only response_type=code is supported in OAuth 2.1'
    });
  }

  // 2. Validate client_id
  if (!client_id) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id is required'
    });
  }

  const client = models.getClientByClientId(client_id);
  if (!client) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client_id'
    });
  }

  if (client.revoked) {
    return res.status(403).json({
      error: 'access_denied',
      error_description: 'This MCP client has been revoked'
    });
  }

  // 3. Validate redirect_uri
  if (!redirect_uri) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'redirect_uri is required'
    });
  }

  // If client has registered redirect URIs, enforce whitelist
  if (client.allowed_redirect_uris && client.allowed_redirect_uris.length > 0) {
    const isAllowed = client.allowed_redirect_uris.some(uri => {
      if (uri === redirect_uri) return true;
      // Allow localhost with any port for native/desktop agent redirects
      if (redirect_uri.startsWith('http://127.0.0.1:') || redirect_uri.startsWith('http://localhost:')) {
        return uri.startsWith('http://127.0.0.1') || uri.startsWith('http://localhost');
      }
      return false;
    });

    if (!isAllowed) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'redirect_uri is not whitelisted for this client'
      });
    }
  }

  // 4. Validate PKCE (Mandatory in OAuth 2.1)
  if (!code_challenge) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code_challenge is required (PKCE is mandatory in OAuth 2.1)'
    });
  }

  if (!code_challenge_method || code_challenge_method.toUpperCase() !== 'S256') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code_challenge_method must be S256'
    });
  }

  try {
    const authCode = oauthService.createAuthorizationCode({
      clientId: client.client_id,
      audience: client.audience,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: 'S256',
      scope
    });

    // Construct redirect URL
    const url = new URL(redirect_uri);
    url.searchParams.set('code', authCode);
    if (state) {
      url.searchParams.set('state', state);
    }

    // Redirect to the client's redirect URI
    return res.redirect(302, url.toString());
  } catch (err) {
    return res.status(500).json({
      error: 'server_error',
      error_description: err.message
    });
  }
});

/**
 * OAuth 2.1 /token endpoint
 * Supports authorization_code (PKCE) and client_credentials grants
 */
router.post('/token', tokenLimiter, async (req, res) => {
  try {
    let {
      grant_type,
      code,
      redirect_uri,
      code_verifier,
      client_id,
      client_secret,
      scope = 'mcp:all'
    } = req.body;

    // Check for HTTP Basic Authorization header (RFC 6749 2.3.1)
    if (req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts[0].toLowerCase() === 'basic' && parts[1]) {
        const decoded = Buffer.from(parts[1], 'base64').toString('utf8');
        const [u, p] = decoded.split(':');
        if (u) client_id = decodeURIComponent(u);
        if (p) client_secret = decodeURIComponent(p);
      }
    }

    if (!grant_type) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'grant_type parameter is required'
      });
    }

    // Case 1: authorization_code (Mode 1 PKCE)
    if (grant_type === 'authorization_code') {
      if (!code) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'code is required'
        });
      }
      if (!code_verifier) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'code_verifier is required for PKCE'
        });
      }
      if (!client_id) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'client_id is required'
        });
      }

      const result = oauthService.exchangeAuthorizationCode({
        code,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeVerifier: code_verifier,
        ipAddress: req.ip
      });

      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      return res.json(result);
    }

    // Case 2: client_credentials (Machine-to-Machine)
    if (grant_type === 'client_credentials') {
      if (!client_id || !client_secret) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'client_id and client_secret are required'
        });
      }

      const result = await oauthService.exchangeClientCredentials({
        clientId: client_id,
        clientSecret: client_secret,
        scope,
        ipAddress: req.ip
      });

      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      return res.json(result);
    }

    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: `Grant type "${grant_type}" is not supported.`
    });
  } catch (err) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: err.message
    });
  }
});

/**
 * RFC 7662 Token Introspection
 */
router.post('/introspect', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.json({ active: false });
  }

  const result = oauthService.introspectToken(token, req.ip);
  res.json(result);
});

/**
 * Revocations List endpoint
 * Returns list of revoked clients for instantaneous local verification checks by MCP servers
 */
router.get('/revocations', (req, res) => {
  const revokedClientIds = models.getRevokedClientIds();
  res.setHeader('Cache-Control', 'no-cache');
  res.json({
    revoked_client_ids: revokedClientIds,
    updated_at: new Date().toISOString()
  });
});

module.exports = router;
