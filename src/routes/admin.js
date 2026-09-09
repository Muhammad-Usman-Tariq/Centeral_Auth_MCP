const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const models = require('../db/models');
const clientService = require('../services/clientService');
const { signAdminToken } = require('../crypto/tokens');
const adminAuth = require('../middleware/adminAuth');
const { adminLoginLimiter } = require('../middleware/rateLimiter');
const config = require('../config');

/**
 * Admin Login
 */
router.post('/login', adminLoginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password are required'
    });
  }

  const admin = models.getAdminByUsername(username);
  if (!admin) {
    return res.status(401).json({
      success: false,
      message: 'Invalid username or password'
    });
  }

  const valid = await bcrypt.compare(password, admin.password_hash);
  if (!valid) {
    return res.status(401).json({
      success: false,
      message: 'Invalid username or password'
    });
  }

  const token = signAdminToken(admin.username);

  models.addTokenEvent({
    clientId: 'admin',
    audience: 'admin-dashboard',
    eventType: 'admin_login',
    mode: 'admin',
    details: { username: admin.username },
    ipAddress: req.ip
  });

  return res.json({
    success: true,
    token,
    user: {
      id: admin.id,
      username: admin.username
    }
  });
});

/**
 * Dashboard Statistics
 */
router.get('/api/stats', adminAuth, (req, res) => {
  const clients = models.listClients();
  const recentEvents = models.getRecentEvents(100);

  const totalClients = clients.length;
  const activeClients = clients.filter(c => !c.revoked).length;
  const revokedClients = clients.filter(c => c.revoked).length;
  const totalEvents = recentEvents.length;

  res.json({
    success: true,
    stats: {
      totalClients,
      activeClients,
      revokedClients,
      totalEvents
    }
  });
});

/**
 * List all registered MCP Clients
 */
router.get('/api/clients', adminAuth, (req, res) => {
  const clients = models.listClients();
  res.json({
    success: true,
    clients
  });
});

/**
 * Create a new MCP Client
 */
router.post('/api/clients', adminAuth, async (req, res) => {
  try {
    const {
      name,
      audience,
      allowedRedirectUris = [],
      generateStaticToken = true,
      staticTokenDays = config.staticTokenExpiryDays
    } = req.body;

    if (!name || !audience) {
      return res.status(400).json({
        success: false,
        message: 'MCP name and audience are required'
      });
    }

    const { client, clientSecret } = await clientService.registerClient({
      name,
      audience,
      allowedRedirectUris,
      clientType: 'confidential',
      ipAddress: req.ip
    });

    let staticTokenData = null;
    if (generateStaticToken) {
      staticTokenData = clientService.generateStaticToken(
        client.client_id,
        staticTokenDays,
        req.ip
      );
    }

    res.status(201).json({
      success: true,
      client,
      clientSecret, // Revealed ONCE
      staticToken: staticTokenData
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

/**
 * Revoke an MCP Client
 */
router.post('/api/clients/:id/revoke', adminAuth, (req, res) => {
  try {
    const client = clientService.revokeClient(req.params.id, req.ip);
    res.json({
      success: true,
      client
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

/**
 * Unrevoke / Restore an MCP Client
 */
router.post('/api/clients/:id/unrevoke', adminAuth, (req, res) => {
  try {
    const client = clientService.unrevokeClient(req.params.id, req.ip);
    res.json({
      success: true,
      client
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

/**
 * Generate a new static long-lived token (Mode 2) for an MCP client
 */
router.post('/api/clients/:id/static-token', adminAuth, (req, res) => {
  try {
    const client = models.getClientById(req.params.id);
    if (!client) {
      return res.status(404).json({ success: false, message: 'Client not found' });
    }

    const days = parseInt(req.body.days || config.staticTokenExpiryDays, 10);
    const staticToken = clientService.generateStaticToken(client.client_id, days, req.ip);

    res.json({
      success: true,
      staticToken
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

/**
 * Audit Log (Last 50-100 events)
 */
router.get('/api/audit', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const events = models.getRecentEvents(limit);

  res.json({
    success: true,
    events
  });
});

module.exports = router;
