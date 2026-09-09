const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const config = require('../config');

let db = null;

function initDatabase() {
  if (db) return db;

  const dbDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  db = new Database(config.dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Run schema migration
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_clients (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      client_id TEXT UNIQUE NOT NULL,
      client_secret_hash TEXT NOT NULL,
      audience TEXT UNIQUE NOT NULL,
      allowed_redirect_uris TEXT DEFAULT '[]',
      client_type TEXT DEFAULT 'confidential',
      revoked INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_mcp_clients_client_id ON mcp_clients(client_id);
    CREATE INDEX IF NOT EXISTS idx_mcp_clients_audience ON mcp_clients(audience);

    CREATE TABLE IF NOT EXISTS token_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT,
      audience TEXT,
      event_type TEXT NOT NULL, -- 'issued', 'failed', 'revoked', 'introspected'
      mode TEXT,                -- 'oauth2_code', 'client_credentials', 'static_token', 'admin'
      details TEXT,
      ip_address TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_token_events_timestamp ON token_events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_token_events_client_id ON token_events(client_id);

    CREATE TABLE IF NOT EXISTS auth_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      audience TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      code_challenge_method TEXT NOT NULL,
      scope TEXT,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      FOREIGN KEY(client_id) REFERENCES mcp_clients(client_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      revoked_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Ensure default admin user
  const adminStmt = db.prepare('SELECT id FROM admin_users WHERE username = ?');
  const existingAdmin = adminStmt.get(config.adminUsername);

  if (!existingAdmin) {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(config.adminPassword, salt);
    const insertAdmin = db.prepare(
      'INSERT INTO admin_users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)'
    );
    insertAdmin.run(
      'admin-default-id',
      config.adminUsername,
      hash,
      new Date().toISOString()
    );
    console.log(`[Database] Initialized default admin user: ${config.adminUsername}`);
  }

  return db;
}

function getDb() {
  if (!db) return initDatabase();
  return db;
}

module.exports = {
  initDatabase,
  getDb
};
