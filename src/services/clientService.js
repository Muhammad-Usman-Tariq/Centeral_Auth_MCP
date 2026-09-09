const crypto = require('crypto');
const models = require('../db/models');
const {
  generateClientId,
  generateClientSecret,
  hashSecret,
  verifySecret,
  signStaticToken
} = require('../crypto/tokens');
const config = require('../config');

const clientService = {
  /**
   * Registers a new MCP client.
   * Can be invoked via Admin UI or RFC 7591 Dynamic Client Registration.
   */
  async registerClient({
    name,
    audience,
    allowedRedirectUris = [],
    clientType = 'confidential',
    ipAddress = null
  }) {
    if (!name || !audience) {
      throw new Error('Both name and audience are required');
    }

    // Ensure audience is clean and unique
    const cleanAudience = audience.trim();
    const existingAud = models.getClientByAudience(cleanAudience);
    if (existingAud) {
      throw new Error(`An MCP client with audience "${cleanAudience}" already exists`);
    }

    const clientId = generateClientId(name);
    const rawSecret = generateClientSecret();
    const secretHash = await hashSecret(rawSecret);
    const id = crypto.randomUUID();

    const client = models.createClient({
      id,
      name: name.trim(),
      clientId,
      clientSecretHash: secretHash,
      audience: cleanAudience,
      allowedRedirectUris,
      clientType
    });

    models.addTokenEvent({
      clientId,
      audience: cleanAudience,
      eventType: 'registered',
      mode: 'admin_or_dcr',
      details: { name: client.name, clientType },
      ipAddress
    });

    return {
      client,
      clientSecret: rawSecret // Revealed ONCE to the caller
    };
  },

  /**
   * Generates a Mode 2 static long-lived token for an MCP client.
   */
  generateStaticToken(clientId, days = config.staticTokenExpiryDays, ipAddress = null) {
    const client = models.getClientByClientId(clientId);
    if (!client) {
      throw new Error('Client not found');
    }
    if (client.revoked) {
      throw new Error('Cannot issue token for a revoked client');
    }

    const { token, jti, expiresIn } = signStaticToken({
      clientId: client.client_id,
      audience: client.audience,
      days
    });

    models.addTokenEvent({
      clientId: client.client_id,
      audience: client.audience,
      eventType: 'issued',
      mode: 'static_token',
      details: { jti, days, expiresIn },
      ipAddress
    });

    return {
      token,
      jti,
      expiresIn,
      audience: client.audience,
      clientId: client.client_id,
      tokenType: 'Bearer'
    };
  },

  /**
   * Authenticates client credentials.
   */
  async authenticateClient(clientId, clientSecret) {
    const client = models.getClientByClientId(clientId);
    if (!client) return null;
    if (client.revoked) return null;

    const valid = await verifySecret(clientSecret, client.client_secret_hash);
    if (!valid) return null;

    return client;
  },

  /**
   * Revokes an MCP client immediately.
   */
  revokeClient(id, ipAddress = null) {
    const client = models.getClientById(id);
    if (!client) throw new Error('Client not found');

    models.updateClientRevocation(id, true);

    models.addTokenEvent({
      clientId: client.client_id,
      audience: client.audience,
      eventType: 'revoked',
      mode: 'admin',
      details: { action: 'revoke_client' },
      ipAddress
    });

    return models.getClientById(id);
  },

  /**
   * Restores/unrevokes an MCP client.
   */
  unrevokeClient(id, ipAddress = null) {
    const client = models.getClientById(id);
    if (!client) throw new Error('Client not found');

    models.updateClientRevocation(id, false);

    models.addTokenEvent({
      clientId: client.client_id,
      audience: client.audience,
      eventType: 'restored',
      mode: 'admin',
      details: { action: 'unrevoke_client' },
      ipAddress
    });

    return models.getClientById(id);
  }
};

module.exports = clientService;
