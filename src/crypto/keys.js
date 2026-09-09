const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');

let privateKey = null;
let publicKey = null;
let jwksCache = null;
let keyId = null;

/**
 * Initializes and loads the RS256 RSA Key Pair.
 * Priority:
 * 1. Environment variables (PRIVATE_KEY_PEM / PUBLIC_KEY_PEM)
 * 2. File system in keysDir (private.pem / public.pem)
 * 3. Auto-generate new 2048-bit RSA keypair and save locally
 */
function initKeys() {
  if (privateKey && publicKey) {
    return { privateKey, publicKey, keyId };
  }

  let privPem = config.privateKeyPem;
  let pubPem = config.publicKeyPem;

  const privPath = path.join(config.keysDir, 'private.pem');
  const pubPath = path.join(config.keysDir, 'public.pem');

  if (!privPem && fs.existsSync(privPath)) {
    privPem = fs.readFileSync(privPath, 'utf8');
  }
  if (!pubPem && fs.existsSync(pubPath)) {
    pubPem = fs.readFileSync(pubPath, 'utf8');
  }

  if (!privPem || !pubPem) {
    console.log('[Crypto] No RS256 keypair found. Generating new 2048-bit RSA keypair...');
    if (!fs.existsSync(config.keysDir)) {
      fs.mkdirSync(config.keysDir, { recursive: true });
    }

    const { privateKey: genPriv, publicKey: genPub } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    privPem = genPriv;
    pubPem = genPub;

    fs.writeFileSync(privPath, privPem, { mode: 0o600 });
    fs.writeFileSync(pubPath, pubPem, { mode: 0o644 });
    console.log(`[Crypto] RS256 keypair saved to ${config.keysDir}`);
  }

  privateKey = privPem;
  publicKey = pubPem;

  // Calculate deterministic kid from public key sha256
  const hash = crypto.createHash('sha256').update(pubPem).digest('hex');
  keyId = `mcp-key-${hash.substring(0, 10)}`;

  // Generate JWKS
  const pubKeyObj = crypto.createPublicKey(pubPem);
  const jwk = pubKeyObj.export({ format: 'jwk' });
  jwk.kid = keyId;
  jwk.use = 'sig';
  jwk.alg = 'RS256';

  jwksCache = {
    keys: [jwk]
  };

  return { privateKey, publicKey, keyId, jwks: jwksCache };
}

function getPrivateKey() {
  if (!privateKey) initKeys();
  return privateKey;
}

function getPublicKey() {
  if (!publicKey) initKeys();
  return publicKey;
}

function getKeyId() {
  if (!keyId) initKeys();
  return keyId;
}

function getJwks() {
  if (!jwksCache) initKeys();
  return jwksCache;
}

module.exports = {
  initKeys,
  getPrivateKey,
  getPublicKey,
  getKeyId,
  getJwks
};
