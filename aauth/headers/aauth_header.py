"""AAuth HTTP response header parsing and building.

Per spec Section 6, the AAuth header is a Structured Fields Dictionary (RFC 8941)
with a `require` key indicating the requirement level.
"""

import re
from typing import Dict, Any, Optional
from ..errors import ChallengeError


# Requirement levels
REQUIRE_PSEUDONYM = "pseudonym"
REQUIRE_IDENTITY = "identity"
REQUIRE_AUTH_TOKEN = "auth-token"
REQUIRE_INTERACTION = "interaction"
REQUIRE_APPROVAL = "approval"


def parse_aauth_header(header_value: str) -> Dict[str, Any]:
    """Parse AAuth response header.

    Formats:
        AAuth: require=pseudonym
        AAuth: require=identity
        AAuth: require=auth-token; resource-token="..."; auth-server="..."
        AAuth: require=interaction; code="ABCD1234"
        AAuth: require=approval

    Args:
        header_value: AAuth header value

    Returns:
        Dictionary with:
        - require: str (pseudonym|identity|auth-token|interaction|approval)
        - resource_token: Optional[str]
        - auth_server: Optional[str]
        - code: Optional[str]

    Raises:
        ChallengeError: If header format is invalid
    """
    try:
        result = {
            "require": None,
            "resource_token": None,
            "auth_server": None,
            "code": None,
        }

        # Extract require value
        require_match = re.search(r'require=([\w-]+)', header_value)
        if not require_match:
            raise ChallengeError("AAuth header must include 'require' parameter")

        result["require"] = require_match.group(1)

        # Extract resource-token parameter
        rt_match = re.search(r'resource-token="([^"]+)"', header_value)
        if rt_match:
            result["resource_token"] = rt_match.group(1)

        # Extract auth-server parameter
        as_match = re.search(r'auth-server="([^"]+)"', header_value)
        if as_match:
            result["auth_server"] = as_match.group(1)

        # Extract code parameter
        code_match = re.search(r'code="([^"]+)"', header_value)
        if code_match:
            result["code"] = code_match.group(1)

        return result

    except ChallengeError:
        raise
    except Exception as e:
        raise ChallengeError(f"Failed to parse AAuth header: {e}") from e


def build_pseudonym_challenge() -> str:
    """Build AAuth challenge requiring pseudonymous signature.

    Returns:
        AAuth header value: require=pseudonym
    """
    return "require=pseudonym"


def build_identity_challenge() -> str:
    """Build AAuth challenge requiring verified agent identity.

    Returns:
        AAuth header value: require=identity
    """
    return "require=identity"


def build_auth_token_challenge(
    resource_token: str,
    auth_server: str
) -> str:
    """Build AAuth challenge requiring an auth token.

    Args:
        resource_token: Resource token JWT string
        auth_server: Auth server URL

    Returns:
        AAuth header value with resource-token and auth-server
    """
    return f'require=auth-token; resource-token="{resource_token}"; auth-server="{auth_server}"'


def build_interaction_challenge(code: str) -> str:
    """Build AAuth response indicating user interaction is required.

    Args:
        code: Interaction code (short alphanumeric)

    Returns:
        AAuth header value with interaction code
    """
    return f'require=interaction; code="{code}"'


def build_approval_challenge() -> str:
    """Build AAuth response indicating approval is pending.

    Returns:
        AAuth header value: require=approval
    """
    return "require=approval"


# --- Backward compatibility aliases ---
# These map the old Agent-Auth API to the new AAuth header API

def build_agent_auth_challenge(
    require_signature: bool = True,
    require_identity: bool = False,
    require_auth_token: bool = False,
    resource_token: Optional[str] = None,
    auth_server: Optional[str] = None,
    **kwargs
) -> str:
    """Build AAuth challenge header (backward-compatible API).

    Maps old Agent-Auth parameters to new AAuth header format.
    """
    if require_auth_token and resource_token and auth_server:
        return build_auth_token_challenge(resource_token, auth_server)
    elif require_identity:
        return build_identity_challenge()
    else:
        return build_pseudonym_challenge()


def parse_agent_auth_header(header_value: str) -> Dict[str, Any]:
    """Parse AAuth header with backward-compatible result format.

    Returns dict compatible with old Agent-Auth parser.
    """
    parsed = parse_aauth_header(header_value)

    # Map to old format for backward compatibility
    result = {
        "httpsig": True,
        "identity": parsed["require"] == REQUIRE_IDENTITY,
        "auth_token": parsed["require"] == REQUIRE_AUTH_TOKEN,
        "resource_token": parsed.get("resource_token"),
        "auth_server": parsed.get("auth_server"),
        "require": parsed["require"],
        "code": parsed.get("code"),
    }
    return result
