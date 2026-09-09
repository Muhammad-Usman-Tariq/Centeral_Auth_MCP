const express = require('express');
const { createMcpAuthMiddleware } = require('../../sdk/node/mcp-auth-middleware');

const app = express();
app.use(express.json());

const PORT = process.env.MCP_SERVER_PORT || 4000;
const AUDIENCE = process.env.MCP_AUTH_AUDIENCE || 'mcp-invoicing';
const JWKS_URI = process.env.MCP_AUTH_JWKS_URI || 'http://localhost:3000/.well-known/jwks.json';

console.log(`[MCP Server] Initializing for audience: "${AUDIENCE}"`);
console.log(`[MCP Server] Pointing to JWKS: ${JWKS_URI}`);

// ========================================================================
// THE ONLY AUTH CODE THE DEVELOPER EVER WRITES:
// ========================================================================
app.use(createMcpAuthMiddleware({
  jwksUri: JWKS_URI,
  audience: AUDIENCE
}));
// ========================================================================

// Health check (if placed after auth, even health check is protected, or place before if public)
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', audience: AUDIENCE });
});

// Standard MCP Tool Endpoints
app.post('/tools/list', (req, res) => {
  // req.mcpClient has { clientId, audience, authMode, jti }
  console.log(`[MCP Server] List tools called by client: ${req.mcpClient.clientId} (Mode: ${req.mcpClient.authMode})`);
  
  res.json({
    tools: [
      {
        name: 'create_invoice',
        description: 'Creates a validated tax invoice',
        inputSchema: {
          type: 'object',
          properties: {
            amount: { type: 'number' },
            recipient: { type: 'string' }
          },
          required: ['amount', 'recipient']
        }
      },
      {
        name: 'get_invoice',
        description: 'Fetches details of an invoice',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string' }
          },
          required: ['id']
        }
      }
    ]
  });
});

app.post('/tools/call', (req, res) => {
  const { name, arguments: args } = req.body;
  console.log(`[MCP Server] Tool "${name}" invoked by client: ${req.mcpClient.clientId}`);

  if (name === 'create_invoice') {
    return res.json({
      content: [
        {
          type: 'text',
          text: `Invoice created successfully for ${args?.recipient || 'Customer'} in the amount of $${args?.amount || 0}. Auth mode used: ${req.mcpClient.authMode}.`
        }
      ]
    });
  }

  res.status(404).json({ error: `Tool ${name} not found` });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[MCP Server] Running at http://localhost:${PORT}`);
    console.log(`[MCP Server] Drop-in auth middleware active. Ready for Claude, Cursor, and all LLMs.`);
  });
}

module.exports = app;
