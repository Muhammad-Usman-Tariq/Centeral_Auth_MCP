from fastapi import Depends, HTTPException, status, Header
from typing import Optional, Dict, Any
from src_py.crypto.tokens import verify_admin_token


async def get_current_admin(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Dependency to authenticate Admin requests via Authorization: Bearer <admin_token>."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "unauthorized",
                "message": "Authorization header required"
            }
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "invalid_token",
                "message": "Format must be: Bearer <token>"
            }
        )

    try:
        payload = verify_admin_token(parts[1])
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "invalid_token",
                "message": "Admin session expired or invalid"
            }
        )
