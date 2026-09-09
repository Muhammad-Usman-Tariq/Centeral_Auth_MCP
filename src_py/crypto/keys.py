import os
import hashlib
import base64
from pathlib import Path
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from src_py.config import settings

_private_key_pem: str = None
_public_key_pem: str = None
_key_id: str = None
_jwks_cache: Dict[str, Any] = None


def int_to_base64url(val: int) -> str:
    """Encodes a large integer to base64url format without padding (RFC 7517 / RFC 7518)."""
    byte_len = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_len, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).decode("ascii").rstrip("=")


def init_keys() -> Tuple[str, str, str, Dict[str, Any]]:
    """
    Initializes and loads the RS256 RSA Key Pair.
    Priority:
    1. Environment variables (PRIVATE_KEY_PEM / PUBLIC_KEY_PEM)
    2. File system in keys_dir (private.pem / public.pem)
    3. Auto-generate new 2048-bit RSA keypair and persist locally
    """
    global _private_key_pem, _public_key_pem, _key_id, _jwks_cache

    if _private_key_pem and _public_key_pem:
        return _private_key_pem, _public_key_pem, _key_id, _jwks_cache

    priv_pem = settings.private_key_pem
    pub_pem = settings.public_key_pem

    keys_dir = Path(settings.keys_dir)
    priv_path = keys_dir / "private.pem"
    pub_path = keys_dir / "public.pem"

    if not priv_pem and priv_path.exists():
        priv_pem = priv_path.read_text(encoding="utf-8")
    if not pub_pem and pub_path.exists():
        pub_pem = pub_path.read_text(encoding="utf-8")

    if not priv_pem or not pub_pem:
        print("[Crypto] No RS256 keypair found. Generating new 2048-bit RSA keypair...")
        keys_dir.mkdir(parents=True, exist_ok=True)

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        priv_path.write_text(priv_pem, encoding="utf-8")
        pub_path.write_text(pub_pem, encoding="utf-8")
        print(f"[Crypto] RS256 keypair saved to {keys_dir}")

    _private_key_pem = priv_pem
    _public_key_pem = pub_pem

    # Deterministic kid from public key sha256
    hash_digest = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
    _key_id = f"mcp-key-{hash_digest[:10]}"

    # Load public key to extract RSA numbers for JWKS (n, e)
    public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Loaded key is not an RSA public key")

    public_numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
        "kid": _key_id,
        "use": "sig",
        "alg": "RS256"
    }

    _jwks_cache = {
        "keys": [jwk]
    }

    return _private_key_pem, _public_key_pem, _key_id, _jwks_cache


def get_private_key_pem() -> str:
    if not _private_key_pem:
        init_keys()
    return _private_key_pem


def get_public_key_pem() -> str:
    if not _public_key_pem:
        init_keys()
    return _public_key_pem


def get_key_id() -> str:
    if not _key_id:
        init_keys()
    return _key_id


def get_jwks() -> Dict[str, Any]:
    if not _jwks_cache:
        init_keys()
    return _jwks_cache
