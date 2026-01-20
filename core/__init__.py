# Core AAuth utilities
# DEPRECATED: This module is deprecated. Use 'aauth' package instead.
# This shim provides backward compatibility during migration.

import warnings
import os

# Debug utilities (kept for backward compatibility)
AAUTH_DEBUG_DEFAULT = "0"
AAUTH_DEBUG_HTTP_DEFAULT = "1"
AAUTH_DEBUG_JWT_TOKEN_DEFAULT = "1"


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled.
    
    Args:
        env_var: Environment variable name to check (default: "AAUTH_DEBUG")
        
    Returns:
        True if debug is enabled, False otherwise.
        Defaults to True unless explicitly disabled via environment variable.
    """
    value = os.environ.get(env_var, AAUTH_DEBUG_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_http_debug_enabled() -> bool:
    """Check if HTTP debug is enabled.
    
    Returns:
        True if HTTP debug is enabled, False otherwise.
        Defaults to True unless explicitly disabled via AAUTH_DEBUG_HTTP environment variable.
    """
    value = os.environ.get("AAUTH_DEBUG_HTTP", AAUTH_DEBUG_HTTP_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_jwt_token_debug_enabled() -> bool:
    """Check if JWT token debug (decoding/printing) is enabled.
    
    Returns:
        True if JWT token debug is enabled, False otherwise.
        Defaults to True unless explicitly disabled via AAUTH_DEBUG_JWT_TOKEN environment variable.
    """
    value = os.environ.get("AAUTH_DEBUG_JWT_TOKEN", AAUTH_DEBUG_JWT_TOKEN_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


# Re-export from aauth with deprecation warnings
def _deprecated_import(name: str, new_location: str):
    """Create a deprecation warning for imports."""
    warnings.warn(
        f"Importing '{name}' from 'core' is deprecated. "
        f"Use 'from {new_location} import {name}' instead. "
        "This compatibility shim will be removed in a future version.",
        DeprecationWarning,
        stacklevel=3
    )


# Re-export httpsig functions
def sign_request(*args, **kwargs):
    _deprecated_import("sign_request", "aauth.signing")
    from aauth.signing import sign_request as _sign_request
    return _sign_request(*args, **kwargs)


def verify_signature(*args, **kwargs):
    _deprecated_import("verify_signature", "aauth.signing")
    from aauth.signing import verify_signature as _verify_signature
    return _verify_signature(*args, **kwargs)


def build_signature_key_header(*args, **kwargs):
    _deprecated_import("build_signature_key_header", "aauth.headers.signature_key")
    from aauth.headers.signature_key import build_signature_key_header as _build
    return _build(*args, **kwargs)


def parse_signature_key(*args, **kwargs):
    _deprecated_import("parse_signature_key", "aauth.headers.signature_key")
    from aauth.headers.signature_key import parse_signature_key as _parse
    return _parse(*args, **kwargs)


def parse_signature_input(*args, **kwargs):
    _deprecated_import("parse_signature_input", "aauth.headers.signature_input")
    from aauth.headers.signature_input import parse_signature_input as _parse
    return _parse(*args, **kwargs)


# Re-export crypto_utils functions
def generate_ed25519_keypair(*args, **kwargs):
    _deprecated_import("generate_ed25519_keypair", "aauth.keys.keypair")
    from aauth.keys.keypair import generate_ed25519_keypair as _generate
    return _generate(*args, **kwargs)


def public_key_to_jwk(*args, **kwargs):
    _deprecated_import("public_key_to_jwk", "aauth.keys.jwk")
    from aauth.keys.jwk import public_key_to_jwk as _convert
    return _convert(*args, **kwargs)


def jwk_to_public_key(*args, **kwargs):
    _deprecated_import("jwk_to_public_key", "aauth.keys.jwk")
    from aauth.keys.jwk import jwk_to_public_key as _convert
    return _convert(*args, **kwargs)


def generate_jwks(*args, **kwargs):
    _deprecated_import("generate_jwks", "aauth.keys.jwk")
    from aauth.keys.jwk import generate_jwks as _generate
    return _generate(*args, **kwargs)


# Re-export tokens functions
def create_resource_token(*args, **kwargs):
    _deprecated_import("create_resource_token", "aauth.tokens.resource_token")
    from aauth.tokens.resource_token import create_resource_token as _create
    return _create(*args, **kwargs)


def create_auth_token(*args, **kwargs):
    _deprecated_import("create_auth_token", "aauth.tokens.auth_token")
    from aauth.tokens.auth_token import create_auth_token as _create
    return _create(*args, **kwargs)


def create_agent_token(*args, **kwargs):
    _deprecated_import("create_agent_token", "aauth.tokens.agent_token")
    from aauth.tokens.agent_token import create_agent_token as _create
    return _create(*args, **kwargs)


def verify_agent_token(*args, **kwargs):
    _deprecated_import("verify_agent_token", "aauth.tokens.agent_token")
    from aauth.tokens.agent_token import verify_agent_token as _verify
    return _verify(*args, **kwargs)


def parse_token_claims(*args, **kwargs):
    _deprecated_import("parse_token_claims", "aauth.tokens.auth_token")
    from aauth.tokens.auth_token import parse_token_claims as _parse
    return _parse(*args, **kwargs)


def calculate_jwk_thumbprint(*args, **kwargs):
    _deprecated_import("calculate_jwk_thumbprint", "aauth.keys.jwk")
    from aauth.keys.jwk import calculate_jwk_thumbprint as _calculate
    return _calculate(*args, **kwargs)


# Re-export metadata functions
def generate_agent_metadata(*args, **kwargs):
    _deprecated_import("generate_agent_metadata", "aauth.metadata.agent")
    from aauth.metadata.agent import generate_agent_metadata as _generate
    return _generate(*args, **kwargs)


def generate_resource_metadata(*args, **kwargs):
    _deprecated_import("generate_resource_metadata", "aauth.metadata.resource")
    from aauth.metadata.resource import generate_resource_metadata as _generate
    return _generate(*args, **kwargs)


def generate_auth_metadata(*args, **kwargs):
    _deprecated_import("generate_auth_metadata", "aauth.metadata.auth_server")
    from aauth.metadata.auth_server import generate_auth_metadata as _generate
    return _generate(*args, **kwargs)


def fetch_auth_metadata(*args, **kwargs):
    _deprecated_import("fetch_auth_metadata", "aauth.metadata.auth_server")
    from aauth.metadata.auth_server import fetch_auth_metadata as _fetch
    return _fetch(*args, **kwargs)


def fetch_resource_metadata(*args, **kwargs):
    _deprecated_import("fetch_resource_metadata", "aauth.metadata.resource")
    # Note: fetch_resource_metadata doesn't exist in new structure, use fetch_auth_metadata pattern
    warnings.warn(
        "fetch_resource_metadata is deprecated. Use aauth.metadata.resource functions directly.",
        DeprecationWarning,
        stacklevel=2
    )
    # For backward compat, we can create a simple wrapper
    import httpx
    from urllib.parse import urlparse
    url = args[0] if args else kwargs.get("url")
    if not url.startswith("https://"):
        parsed = httpx.URL(url)
        if parsed.host not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(f"Metadata URL must use HTTPS (except localhost): {url}")
    response = httpx.get(url, timeout=10.0)
    response.raise_for_status()
    return response.json()
