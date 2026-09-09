const models = require('../db/models');
const {
  verifyPkceChallenge,
  generateAuthCode,
  signMcpToken,
  verifyMcpToken
} = require('../crypto/tokens');
const config = require('../config');
const clientService = require('./clientService');

const oauthService = {
  /**
   * RFC 8414 Authorization Server Metadata
   */
  getAuthorizationServerMetadata() {
    const base = config.issuerUrl;
    return {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      introspection_endpoint: `${base}/introspect`,
      revocation_endpoint: `${base}/revocations`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'client_credentials'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['mcp:all', 'mcp:read', 'mcp:write'],
      service_documentation: `${base}/admin`,
      ui_locales_supported: ['en']
    };
  },

  /**
   * OAuth 2.1 Protected Resource Metadata (PRM)
   * draft-ietf-oauth-resource-metadata
   */
  getProtectedResourceMetadata(resource = null) {
    const base = config.issuerUrl;
    return {
      resource: resource || base,
      authorization_servers: [base],
      scopes_supported: ['mcp:all'],
      bearer_methods_supported: ['header'],
      resource_documentation: `${base}/admin`
    };
  },

  /**
   * Creates an authorization code for OAuth 2.1 PKCE
   */
  createAuthorizationCode({
    clientId,
    audience,
    redirectUri,
    codeChallenge,
    codeChallengeMethod = 'S256',
    scope = 'mcp:all'
  }) {
    if (codeChallengeMethod !== 'S256') {
      throw new Error('OAuth 2.1 requires code_challenge_method to be S256');
    }
    if (!codeChallenge) {
      throw new Error('OAuth 2.1 requires code_challenge (PKCE)');
    }

    const code = generateAuthCode();
    const expiresAt = Date.now() + (config.authCodeExpirySeconds * 1000);

    models.createAuthCode({
      code,
      clientId,
      audience,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      scope,
      expiresAt
    });

    return code;
  },

  /**
   * Exchanges an authorization code for an RS256 access token
   */
  exchangeAuthorizationCode({
    code,
    clientId,
    redirectUri,
    codeVerifier,
    ipAddress = null
  }) {
    const authCode = models.getAuthCode(code);
    if (!authCode) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'Invalid authorization code',
        ipAddress
      });
      throw new Error('Invalid authorization code');
    }

    if (authCode.used) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'Authorization code already used',
        ipAddress
      });
      throw new Error('Authorization code has already been used');
    }

    if (Date.now() > authCode.expires_at) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'Authorization code expired',
        ipAddress
      });
      throw new Error('Authorization code expired');
    }

    if (authCode.client_id !== clientId) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'Client ID mismatch for authorization code',
        ipAddress
      });
      throw new Error('Client ID mismatch');
    }

    if (authCode.redirect_uri !== redirectUri) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'Redirect URI mismatch',
        ipAddress
      });
      throw new Error('Redirect URI mismatch');
    }

    // Verify PKCE verifier against code challenge
    const pkceValid = verifyPkceChallenge(
      codeVerifier,
      authCode.code_challenge,
      authCode.code_challenge_method
    );

    if (!pkceValid) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'PKCE code_verifier verification failed',
        ipAddress
      });
      throw new Error('Invalid code_verifier for PKCE challenge');
    }

    // Check client revocation status
    const client = models.getClientByClientId(clientId);
    if (!client || client.revoked) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'oauth2_code',
        details: 'Client is revoked or does not exist',
        ipAddress
      });
      throw new Error('Client has been revoked or does not exist');
    }

    // Mark code as used immediately
    models.markAuthCodeUsed(code);

    // Issue RS256 token
    const tokenResult = signMcpToken({
      clientId: client.client_id,
      audience: authCode.audience || client.audience,
      mode: 'oauth2_code',
      expiresInSeconds: config.accessTokenExpiry,
      customClaims: {
        scope: authCode.scope
      }
    });

    models.addTokenEvent({
      clientId: client.client_id,
      audience: client.audience,
      eventType: 'issued',
      mode: 'oauth2_code',
      details: { jti: tokenResult.jti, scope: authCode.scope },
      ipAddress
    });

    return {
      access_token: tokenResult.token,
      token_type: 'Bearer',
      expires_in: tokenResult.expiresIn,
      scope: authCode.scope
    };
  },

  /**
   * Client Credentials Grant (Machine-to-Machine)
   */
  async exchangeClientCredentials({
    clientId,
    clientSecret,
    scope = 'mcp:all',
    ipAddress = null
  }) {
    const client = await clientService.authenticateClient(clientId, clientSecret);
    if (!client) {
      models.addTokenEvent({
        clientId,
        eventType: 'failed',
        mode: 'client_credentials',
        details: 'Invalid client credentials or client revoked',
        ipAddress
      });
      throw new Error('Invalid client credentials or client revoked');
    }

    const tokenResult = signMcpToken({
      clientId: client.client_id,
      audience: client.audience,
      mode: 'client_credentials',
      expiresInSeconds: config.accessTokenExpiry,
      customClaims: { scope }
    });

    models.addTokenEvent({
      clientId: client.client_id,
      audience: client.audience,
      eventType: 'issued',
      mode: 'client_credentials',
      details: { jti: tokenResult.jti, scope },
      ipAddress
    });

    return {
      access_token: tokenResult.token,
      token_type: 'Bearer',
      expires_in: tokenResult.expiresIn,
      scope
    };
  },

  /**
   * RFC 7662 Token Introspection
   */
  introspectToken(token, ipAddress = null) {
    try {
      const decoded = verifyMcpToken(token);

      // Check if client is revoked
      const client = models.getClientByClientId(decoded.sub || decoded.client_id);
      if (!client || client.revoked) {
        return { active: false };
      }

      // Check if individual token JTI is revoked
      if (decoded.jti && models.isTokenJtiRevoked(decoded.jti)) {
        return { active: false };
      }

      models.addTokenEvent({
        clientId: decoded.client_id,
        audience: decoded.aud,
        eventType: 'introspected',
        mode: decoded.auth_mode || 'token',
        details: { jti: decoded.jti, active: true },
        ipAddress
      });

      return {
        active: true,
        client_id: decoded.client_id,
        sub: decoded.sub,
        aud: decoded.aud,
        iss: decoded.iss,
        exp: decoded.exp,
        iat: decoded.iat,
        jti: decoded.jti,
        auth_mode: decoded.auth_mode,
        token_type: 'Bearer'
      };
    } catch (err) {
      return { active: false };
    }
  }
};

module.exports = oauthService;
