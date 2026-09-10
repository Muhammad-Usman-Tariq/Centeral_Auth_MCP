import sys
sys.path.insert(0, './sdk/python')
from fastapi import FastAPI
from mcp_auth_middleware import McpAuthMiddleware

app = FastAPI()
app.add_middleware(
    McpAuthMiddleware,
    jwks_uri="http://localhost:8000/.well-known/jwks.json",
    audience="mcp-invoicing",   # ye MCP SIRF mcp-invoicing audience wale tokens accept karega
)

@app.get("/mcp")
def mcp_endpoint():
    return {"ok": True, "message": "Aap Invoicing MCP ke andar hain"}