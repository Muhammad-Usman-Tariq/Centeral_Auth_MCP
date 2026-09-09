/**
 * Automated Test Suite for Central Auth Server & Drop-in MCP Middleware
 * 
 * Verifies:
 * 1. RFC 8414 Discovery & RFC 7517 JWKS
 * 2. Mode 1: Dynamic Client Registration (RFC 7591)
 * 3. Mode 1: Full OAuth 2.1 Flow with PKCE (S256 mandatory)
 * 4. Mode 1: Client Credentials Grant (M2M)
 * 5. Mode 2: Static Long-Lived Token Issuance
 * 6. Standalone Drop-in MCP Middleware Verification (Zero LLM Code!)
 * 7. Immediate Revocation Invalidation
 * 8. Audit Trail Verification
 */

const http = require('http');
const crypto = require('crypto');
const app = require('../src/app');
const config = require('../src/config');
const { initDatabase, getDb } = require('../src/db/database');
const { initKeys } = require('../src/crypto/keys');
const { createMcpAuthMiddleware } = require('../sdk/node/mcp-auth-middleware');

let server = null;
let serverBaseUrl = '';
let testClientId = '';
let testClientSecret = '';
let testAudience = `mcp-test-invoicing-${Date.now()}`;
let adminToken = '';

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, serverBaseUrl);
    const reqHeaders = { ...headers };
    let postData = null;

    if (body) {
      if (typeof body === 'object') {
        postData = JSON.stringify(body);
        if (!reqHeaders['content-type']) {
          reqHeaders['content-type'] = 'application/json';
        }
      } else {
        postData = body;
      }
      reqHeaders['content-length'] = Buffer.byteLength(postData);
    }

    const req = http.request(
      url,
      {
        method,
        headers: reqHeaders
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed = null;
          try {
            parsed = JSON.parse(raw);
          } catch {
            parsed = raw;
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: parsed
          });
        });
      }
    );

    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

// Colorized test reporting
function assert(condition, message) {
  if (!condition) {
    console.error(`  \x1b[31m✖ FAIL:\x1b[0m ${message}`);
    throw new Error(message);
  }
  console.log(`  \x1b[32m✔ PASS:\x1b[0m ${message}`);
}

async function runTests() {
  console.log('\n======================================================');
  console.log(' RUNNING CENTRAL AUTH MCP TEST SUITE');
  console.log('======================================================\n');

  // Start test server on dynamic port
  initDatabase();
  initKeys();

  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      serverBaseUrl = `http://127.0.0.1:${port}`;
      config.issuerUrl = serverBaseUrl;
      console.log(`[Test Server] Started at ${serverBaseUrl}\n`);
      resolve();
    });
  });

  try {
    // -------------------------------------------------------------
    console.log('\x1b[36m[TEST 1] Discovery & JWKS Endpoints\x1b[0m');
    // -------------------------------------------------------------
    const discRes = await request('GET', '/.well-known/oauth-authorization-server');
    assert(discRes.statusCode === 200, 'Discovery returns HTTP 200');
    assert(discRes.body.issuer === serverBaseUrl, 'Discovery issuer matches');
    assert(discRes.body.code_challenge_methods_supported.includes('S256'), 'Mandates PKCE S256');

    const jwksRes = await request('GET', '/.well-known/jwks.json');
    assert(jwksRes.statusCode === 200, 'JWKS returns HTTP 200');
    assert(Array.isArray(jwksRes.body.keys) && jwksRes.body.keys.length > 0, 'JWKS contains public keys');
    assert(jwksRes.body.keys[0].kty === 'RSA', 'JWKS key type is RSA');
    assert(jwksRes.body.keys[0].alg === 'RS256', 'JWKS algorithm is RS256');

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 2] Admin Authentication & MCP Registration\x1b[0m');
    // -------------------------------------------------------------
    const loginRes = await request('POST', '/admin/login', {
      username: config.adminUsername,
      password: config.adminPassword
    });
    assert(loginRes.statusCode === 200, 'Admin login succeeds');
    assert(Boolean(loginRes.body.token), 'Admin JWT token received');
    adminToken = loginRes.body.token;

    const createRes = await request(
      'POST',
      '/admin/api/clients',
      {
        name: 'Invoicing Microservice',
        audience: testAudience,
        allowedRedirectUris: ['http://127.0.0.1:9999/callback'],
        generateStaticToken: true,
        staticTokenDays: 90
      },
      { authorization: `Bearer ${adminToken}` }
    );
    assert(createRes.statusCode === 201, 'Admin registers new MCP client');
    assert(Boolean(createRes.body.client.client_id), 'Client ID auto-generated');
    assert(Boolean(createRes.body.clientSecret), 'Client Secret revealed ONCE');
    assert(Boolean(createRes.body.staticToken.token), 'Mode 2 static token generated');

    testClientId = createRes.body.client.client_id;
    testClientSecret = createRes.body.clientSecret;
    const staticToken = createRes.body.staticToken.token;

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 3] Mode 1: Dynamic Client Registration (RFC 7591)\x1b[0m');
    // -------------------------------------------------------------
    const dcrRes = await request('POST', '/register', {
      client_name: 'Claude Desktop Agent',
      audience: `mcp-claude-${Date.now()}`,
      redirect_uris: ['http://127.0.0.1:8080/callback']
    });
    assert(dcrRes.statusCode === 201, 'RFC 7591 dynamic registration succeeds');
    assert(Boolean(dcrRes.body.client_id), 'Dynamic client ID issued');
    assert(dcrRes.body.token_endpoint_auth_method === 'client_secret_post', 'Supported auth method set');

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 4] Mode 1: Full OAuth 2.1 PKCE Authorization Code Flow\x1b[0m');
    // -------------------------------------------------------------
    // Generate PKCE code_verifier and S256 code_challenge
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');

    // 1. Authorize Request
    const authUrl = `/.well-known/../authorize?response_type=code&client_id=${testClientId}&redirect_uri=http://127.0.0.1:9999/callback&code_challenge=${codeChallenge}&code_challenge_method=S256&state=state123`;
    const authRes = await request('GET', authUrl);
    assert(authRes.statusCode === 302, 'Authorization endpoint redirects with HTTP 302');
    
    const location = authRes.headers.location;
    assert(Boolean(location), 'Location header present');
    const redirectUrl = new URL(location);
    const authCode = redirectUrl.searchParams.get('code');
    const state = redirectUrl.searchParams.get('state');
    assert(Boolean(authCode), 'Authorization code received in redirect');
    assert(state === 'state123', 'OAuth state preserved');

    // 2. Token Exchange with Invalid PKCE Verifier (Must fail)
    const badTokenRes = await request('POST', '/token', {
      grant_type: 'authorization_code',
      client_id: testClientId,
      code: authCode,
      redirect_uri: 'http://127.0.0.1:9999/callback',
      code_verifier: 'wrong-verifier-code'
    });
    assert(badTokenRes.statusCode === 400, 'Rejects invalid PKCE code_verifier');

    // 3. Token Exchange with Valid PKCE Verifier (Must succeed)
    const goodTokenRes = await request('POST', '/token', {
      grant_type: 'authorization_code',
      client_id: testClientId,
      code: authCode,
      redirect_uri: 'http://127.0.0.1:9999/callback',
      code_verifier: codeVerifier
    });
    assert(goodTokenRes.statusCode === 200, 'Exchanges code for RS256 access token');
    assert(Boolean(goodTokenRes.body.access_token), 'Access token received');
    const oauthAccessToken = goodTokenRes.body.access_token;

    // 4. Replay test (code cannot be reused)
    const replayRes = await request('POST', '/token', {
      grant_type: 'authorization_code',
      client_id: testClientId,
      code: authCode,
      redirect_uri: 'http://127.0.0.1:9999/callback',
      code_verifier: codeVerifier
    });
    assert(replayRes.statusCode === 400, 'Rejects replayed authorization code');

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 5] Mode 1: Client Credentials Grant (M2M)\x1b[0m');
    // -------------------------------------------------------------
    const ccRes = await request('POST', '/token', {
      grant_type: 'client_credentials',
      client_id: testClientId,
      client_secret: testClientSecret
    });
    assert(ccRes.statusCode === 200, 'Client credentials flow succeeds');
    assert(Boolean(ccRes.body.access_token), 'M2M access token received');

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 6] Standalone Drop-in MCP Middleware Verification\x1b[0m');
    // -------------------------------------------------------------
    // Instantiate the exact drop-in middleware any MCP server would use:
    const mcpMiddleware = createMcpAuthMiddleware({
      jwksUri: `${serverBaseUrl}/.well-known/jwks.json`,
      audience: testAudience,
      revocationsUri: `${serverBaseUrl}/revocations`
    });

    function runMiddleware(reqObj) {
      return new Promise((resolve) => {
        const resObj = {
          statusCode: 200,
          headers: {},
          setHeader(k, v) { this.headers[k] = v; },
          status(code) { this.statusCode = code; return this; },
          json(data) { resolve({ status: this.statusCode, body: data, headers: this.headers }); }
        };
        mcpMiddleware(reqObj, resObj, () => {
          resolve({ status: 200, req: reqObj });
        });
      });
    }

    // A) Mode 1 OAuth 2.1 Token via Authorization: Bearer
    const midTest1 = await runMiddleware({
      headers: { authorization: `Bearer ${oauthAccessToken}` }
    });
    assert(midTest1.status === 200, 'Middleware verifies Mode 1 OAuth 2.1 Bearer token');
    assert(midTest1.req.mcpClient.audience === testAudience, 'Middleware populates client context');

    // B) Mode 2 Static Token via x-api-key header
    const midTest2 = await runMiddleware({
      headers: { 'x-api-key': staticToken }
    });
    assert(midTest2.status === 200, 'Middleware verifies Mode 2 static token via x-api-key');

    // C) Reject tampered token
    const midTest3 = await runMiddleware({
      headers: { authorization: `Bearer ${oauthAccessToken}tampered` }
    });
    assert(midTest3.status === 401, 'Middleware rejects tampered token signature');

    // D) Reject mismatched audience
    const mismatchedAudMiddleware = createMcpAuthMiddleware({
      jwksUri: `${serverBaseUrl}/.well-known/jwks.json`,
      audience: 'mcp-wrong-service'
    });
    const midTest4 = await new Promise((resolve) => {
      const resObj = {
        statusCode: 200,
        headers: {},
        setHeader(k, v) { this.headers[k] = v; },
        status(code) { this.statusCode = code; return this; },
        json(data) { resolve({ status: this.statusCode, body: data }); }
      };
      mismatchedAudMiddleware({ headers: { 'x-api-key': staticToken } }, resObj, () => resolve({ status: 200 }));
    });
    assert(midTest4.status === 401, 'Middleware rejects token with wrong audience');

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 7] Immediate Revocation Enforcement\x1b[0m');
    // -------------------------------------------------------------
    // Find client ID in database and revoke
    const clientRecord = getDb().prepare('SELECT id FROM mcp_clients WHERE client_id = ?').get(testClientId);
    const revokeRes = await request(
      'POST',
      `/admin/api/clients/${clientRecord.id}/revoke`,
      {},
      { authorization: `Bearer ${adminToken}` }
    );
    assert(revokeRes.statusCode === 200, 'Admin successfully revokes MCP client');

    // Fast-expire middleware revocation cache for testing
    const midRevokeTest = createMcpAuthMiddleware({
      jwksUri: `${serverBaseUrl}/.well-known/jwks.json`,
      audience: testAudience,
      revocationsUri: `${serverBaseUrl}/revocations`,
      revocationCacheTtlMs: 0 // force instant check
    });

    const revokedAttempt = await new Promise((resolve) => {
      const resObj = {
        statusCode: 200,
        headers: {},
        setHeader(k, v) { this.headers[k] = v; },
        status(code) { this.statusCode = code; return this; },
        json(data) { resolve({ status: this.statusCode, body: data }); }
      };
      midRevokeTest({ headers: { 'x-api-key': staticToken } }, resObj, () => resolve({ status: 200 }));
    });
    assert(revokedAttempt.status === 401, 'Revoked client tokens are immediately rejected');

    // -------------------------------------------------------------
    console.log('\n\x1b[36m[TEST 8] Audit Log Trail Verification\x1b[0m');
    // -------------------------------------------------------------
    const auditRes = await request(
      'GET',
      '/admin/api/audit?limit=20',
      null,
      { authorization: `Bearer ${adminToken}` }
    );
    assert(auditRes.statusCode === 200, 'Audit log endpoint returns 200');
    assert(Array.isArray(auditRes.body.events), 'Audit returns list of events');
    const hasIssued = auditRes.body.events.some(e => e.event_type === 'issued');
    const hasRevoked = auditRes.body.events.some(e => e.event_type === 'revoked');
    assert(hasIssued, 'Audit log records token issuance');
    assert(hasRevoked, 'Audit log records client revocation');

    console.log('\n======================================================');
    console.log('\x1b[32m ALL TESTS PASSED SUCCESSFULLY! (8/8 Suites)\x1b[0m');
    console.log('======================================================\n');
  } finally {
    if (server) {
      server.close();
    }
  }
}

runTests().catch((err) => {
  console.error('\nTest execution failed:', err);
  process.exit(1);
});
