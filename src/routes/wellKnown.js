const express = require('express');
const router = express.Router();
const cors = require('cors');
const { getJwks } = require('../crypto/keys');
const oauthService = require('../services/oauthService');

// All .well-known discovery and key endpoints must allow unrestricted cross-origin requests
// so LLM clients and MCP servers can discover and verify anywhere.
router.use(cors({ origin: '*' }));

/**
 * RFC 8414 OAuth 2.0 / 2.1 Authorization Server Metadata
 */
router.get('/oauth-authorization-server', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json(oauthService.getAuthorizationServerMetadata());
});

/**
 * OAuth 2.1 Protected Resource Metadata (PRM)
 * draft-ietf-oauth-resource-metadata
 */
router.get('/oauth-protected-resource', (req, res) => {
  const resource = req.query.resource;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json(oauthService.getProtectedResourceMetadata(resource));
});

/**
 * RFC 7517 JSON Web Key Set (JWKS)
 * Contains the public RS256 key(s) used by MCP servers to verify signatures
 */
router.get('/jwks.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=300'); // 5 minutes cache
  res.json(getJwks());
});

module.exports = router;
