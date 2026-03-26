"""Debug utilities for AAuth."""

import os

AAUTH_DEBUG_DEFAULT = "0"
AAUTH_DEBUG_HTTP_DEFAULT = "1"
AAUTH_DEBUG_JWT_TOKEN_DEFAULT = "1"


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled.

    Args:
        env_var: Environment variable name to check (default: "AAUTH_DEBUG")

    Returns:
        True if debug is enabled, False otherwise.
    """
    value = os.environ.get(env_var, AAUTH_DEBUG_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_http_debug_enabled() -> bool:
    """Check if HTTP debug is enabled.

    Returns:
        True if HTTP debug is enabled, False otherwise.
    """
    value = os.environ.get("AAUTH_DEBUG_HTTP", AAUTH_DEBUG_HTTP_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_jwt_token_debug_enabled() -> bool:
    """Check if JWT token debug (decoding/printing) is enabled.

    Returns:
        True if JWT token debug is enabled, False otherwise.
    """
    value = os.environ.get("AAUTH_DEBUG_JWT_TOKEN", AAUTH_DEBUG_JWT_TOKEN_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")
