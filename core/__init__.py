# Core AAuth utilities

import os

# Default value for AAUTH_DEBUG environment variable
# Set to "1" to enable debug logging by default, "0" to disable by default
AAUTH_DEBUG_DEFAULT = "0"

# Default value for AAUTH_DEBUG_HTTP environment variable
# Set to "1" to enable HTTP debug logging by default, "0" to disable by default
AAUTH_DEBUG_HTTP_DEFAULT = "1"


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
