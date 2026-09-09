const { getDb } = require('./database');

const models = {
  // Client Management
  createClient({
    id,
    name,
    clientId,
    clientSecretHash,
    audience,
    allowedRedirectUris = [],
    clientType = 'confidential'
  }) {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO mcp_clients 
        (id, name, client_id, client_secret_hash, audience, allowed_redirect_uris, client_type, revoked, created_at)
      VALUES 
        (@id, @name, @clientId, @clientSecretHash, @audience, @allowedRedirectUris, @clientType, 0, @createdAt)
    `);

    stmt.run({
      id,
      name,
      clientId,
      clientSecretHash,
      audience,
      allowedRedirectUris: JSON.stringify(allowedRedirectUris),
      clientType,
      createdAt: new Date().toISOString()
    });

    return models.getClientByClientId(clientId);
  },

  getClientByClientId(clientId) {
    const db = getDb();
    const row = db.prepare('SELECT * FROM mcp_clients WHERE client_id = ?').get(clientId);
    if (!row) return null;
    return {
      ...row,
      revoked: Boolean(row.revoked),
      allowed_redirect_uris: JSON.parse(row.allowed_redirect_uris || '[]')
    };
  },

  getClientById(id) {
    const db = getDb();
    const row = db.prepare('SELECT * FROM mcp_clients WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      revoked: Boolean(row.revoked),
      allowed_redirect_uris: JSON.parse(row.allowed_redirect_uris || '[]')
    };
  },

  getClientByAudience(audience) {
    const db = getDb();
    const row = db.prepare('SELECT * FROM mcp_clients WHERE audience = ?').get(audience);
    if (!row) return null;
    return {
      ...row,
      revoked: Boolean(row.revoked),
      allowed_redirect_uris: JSON.parse(row.allowed_redirect_uris || '[]')
    };
  },

  listClients() {
    const db = getDb();
    const rows = db.prepare('SELECT id, name, client_id, audience, allowed_redirect_uris, client_type, revoked, created_at FROM mcp_clients ORDER BY created_at DESC').all();
    return rows.map(row => ({
      ...row,
      revoked: Boolean(row.revoked),
      allowed_redirect_uris: JSON.parse(row.allowed_redirect_uris || '[]')
    }));
  },

  updateClientRevocation(id, revoked) {
    const db = getDb();
    const stmt = db.prepare('UPDATE mcp_clients SET revoked = ? WHERE id = ?');
    stmt.run(revoked ? 1 : 0, id);
    return models.getClientById(id);
  },

  deleteClient(id) {
    const db = getDb();
    const stmt = db.prepare('DELETE FROM mcp_clients WHERE id = ?');
    stmt.run(id);
  },

  // Auth Codes (OAuth 2.1 PKCE)
  createAuthCode({
    code,
    clientId,
    audience,
    redirectUri,
    codeChallenge,
    codeChallengeMethod,
    scope,
    expiresAt
  }) {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO auth_codes 
        (code, client_id, audience, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used)
      VALUES 
        (@code, @clientId, @audience, @redirectUri, @codeChallenge, @codeChallengeMethod, @scope, @expiresAt, 0)
    `);
    stmt.run({
      code,
      clientId,
      audience,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      scope,
      expiresAt
    });
  },

  getAuthCode(code) {
    const db = getDb();
    return db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(code);
  },

  markAuthCodeUsed(code) {
    const db = getDb();
    db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(code);
  },

  // Token Revocation
  revokeTokenJti(jti, clientId) {
    const db = getDb();
    db.prepare('INSERT OR REPLACE INTO revoked_tokens (jti, client_id, revoked_at) VALUES (?, ?, ?)').run(
      jti,
      clientId,
      new Date().toISOString()
    );
  },

  isTokenJtiRevoked(jti) {
    const db = getDb();
    const row = db.prepare('SELECT jti FROM revoked_tokens WHERE jti = ?').get(jti);
    return Boolean(row);
  },

  getRevokedClientIds() {
    const db = getDb();
    const rows = db.prepare('SELECT client_id FROM mcp_clients WHERE revoked = 1').all();
    return rows.map(r => r.client_id);
  },

  // Audit Log (Token Events)
  addTokenEvent({
    clientId = null,
    audience = null,
    eventType,
    mode = null,
    details = null,
    ipAddress = null
  }) {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO token_events 
        (client_id, audience, event_type, mode, details, ip_address, timestamp)
      VALUES 
        (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      clientId,
      audience,
      eventType,
      mode,
      typeof details === 'object' ? JSON.stringify(details) : details,
      ipAddress,
      new Date().toISOString()
    );
  },

  getRecentEvents(limit = 50) {
    const db = getDb();
    return db.prepare(`
      SELECT * FROM token_events 
      ORDER BY id DESC 
      LIMIT ?
    `).all(limit);
  },

  // Admin User
  getAdminByUsername(username) {
    const db = getDb();
    return db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
  }
};

module.exports = models;
