# Example Protected MCP Server

Demonstrates how trivial it is to protect an MCP server using Central Auth.

## How It Works
1. Imports `createMcpAuthMiddleware`.
2. Applies it across the Express app:
   ```javascript
   app.use(createMcpAuthMiddleware({
     jwksUri: process.env.MCP_AUTH_JWKS_URI || 'http://localhost:3000/.well-known/jwks.json',
     audience: process.env.MCP_AUTH_AUDIENCE || 'mcp-invoicing'
   }));
   ```
3. Exposes standard MCP endpoints (`/tools/list`, `/tools/call`).

## Running the Example

```bash
# Start the central auth server first:
npm start

# In a separate terminal, start this MCP server:
node examples/node-mcp-server/server.js
```

## Testing with Curl

### Without Auth (Fails with 401):
```bash
curl -X POST http://localhost:4000/tools/list
# HTTP 401 Unauthorized
```

### With Static Token (Mode 2 via x-api-key):
```bash
curl -X POST http://localhost:4000/tools/list \
  -H "x-api-key: <STATIC_TOKEN_FROM_ADMIN_PANEL>"
# HTTP 200 OK with tool listings
```

### With OAuth 2.1 Token (Mode 1 via Bearer):
```bash
curl -X POST http://localhost:4000/tools/list \
  -H "Authorization: Bearer <OAUTH_TOKEN>"
# HTTP 200 OK with tool listings
```
