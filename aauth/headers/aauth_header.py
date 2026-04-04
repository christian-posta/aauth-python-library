"""AAuth-Requirement and AAuth-Error HTTP response header parsing and building.

Per the AAuth Headers spec (draft-hardt-aauth-headers), the AAuth-Requirement header
is a Structured Fields Dictionary (RFC 8941) with a `requirement` key indicating
the requirement level. The AAuth-Error header is a Structured Fields Dictionary
with an `error` key indicating the error code.
"""

import re
from typing import Dict, Any, Optional, List
from ..errors import ChallengeError


# Requirement levels
REQUIRE_PSEUDONYM = "pseudonym"
REQUIRE_IDENTITY = "identity"
REQUIRE_AUTH_TOKEN = "auth-token"
REQUIRE_INTERACTION = "interaction"
REQUIRE_APPROVAL = "approval"

# AAuth-Error codes (from draft-hardt-aauth-headers)
ERROR_INVALID_REQUEST = "invalid_request"
ERROR_INVALID_INPUT = "invalid_input"
ERROR_INVALID_SIGNATURE = "invalid_signature"
ERROR_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
ERROR_INVALID_KEY = "invalid_key"
ERROR_UNKNOWN_KEY = "unknown_key"
ERROR_INVALID_JWT = "invalid_jwt"
ERROR_EXPIRED_JWT = "expired_jwt"


def parse_aauth_requirement(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Requirement response header.

    Formats:
        AAuth-Requirement: requirement=pseudonym
        AAuth-Requirement: requirement=identity
        AAuth-Requirement: requirement=auth-token; resource-token="..."; auth-server="..."
        AAuth-Requirement: requirement=interaction; url="..."; code="ABCD1234"
        AAuth-Requirement: requirement=approval

    Args:
        header_value: AAuth-Requirement header value

    Returns:
        Dictionary with:
        - requirement: str (pseudonym|identity|auth-token|interaction|approval)
        - resource_token: Optional[str]
        - auth_server: Optional[str]
        - url: Optional[str]
        - code: Optional[str]

    Raises:
        ChallengeError: If header format is invalid
    """
    try:
        result = {
            "requirement": None,
            "resource_token": None,
            "auth_server": None,
            "url": None,
            "code": None,
        }

        # Extract requirement value
        require_match = re.search(r'requirement=([\w-]+)', header_value)
        if not require_match:
            raise ChallengeError("AAuth-Requirement header must include 'requirement' parameter")

        result["requirement"] = require_match.group(1)

        # Extract resource-token parameter
        rt_match = re.search(r'resource-token="([^"]+)"', header_value)
        if rt_match:
            result["resource_token"] = rt_match.group(1)

        # Extract auth-server parameter
        as_match = re.search(r'auth-server="([^"]+)"', header_value)
        if as_match:
            result["auth_server"] = as_match.group(1)

        # Extract url parameter
        url_match = re.search(r'url="([^"]+)"', header_value)
        if url_match:
            result["url"] = url_match.group(1)

        # Extract code parameter
        code_match = re.search(r'code="([^"]+)"', header_value)
        if code_match:
            result["code"] = code_match.group(1)

        return result

    except ChallengeError:
        raise
    except Exception as e:
        raise ChallengeError(f"Failed to parse AAuth-Requirement header: {e}") from e


def build_pseudonym_requirement() -> str:
    """Build AAuth-Requirement requiring pseudonymous signature.

    Returns:
        AAuth-Requirement header value: requirement=pseudonym
    """
    return "requirement=pseudonym"


def build_identity_requirement() -> str:
    """Build AAuth-Requirement requiring verified agent identity.

    Returns:
        AAuth-Requirement header value: requirement=identity
    """
    return "requirement=identity"


def build_auth_token_requirement(
    resource_token: str,
    auth_server: str = None,
) -> str:
    """Build AAuth-Requirement requiring an auth token.

    Per spec, the auth server is discovered from the resource token's aud claim,
    not from a separate parameter. The auth_server parameter is accepted for
    backward compatibility but not included in the header.

    Args:
        resource_token: Resource token JWT string
        auth_server: Deprecated - auth server discovered from resource token aud

    Returns:
        AAuth-Requirement header value with resource-token
    """
    return f'requirement=auth-token; resource-token="{resource_token}"'


def build_interaction_requirement(url: str, code: str) -> str:
    """Build AAuth-Requirement indicating user interaction is required.

    Args:
        url: Interaction URL (HTTPS, no query or fragment)
        code: Interaction code (short alphanumeric)

    Returns:
        AAuth-Requirement header value with url and interaction code
    """
    return f'requirement=interaction; url="{url}"; code="{code}"'


def build_approval_requirement() -> str:
    """Build AAuth-Requirement indicating approval is pending.

    Returns:
        AAuth-Requirement header value: requirement=approval
    """
    return "requirement=approval"


# --- AAuth-Error header ---

def build_aauth_error(
    error: str,
    required_input: Optional[List[str]] = None,
    supported_algorithms: Optional[List[str]] = None,
) -> str:
    """Build AAuth-Error header value per draft-hardt-aauth-headers.

    The AAuth-Error header is a Structured Fields Dictionary (RFC 8941)
    with an `error` token and optional parameters.

    Args:
        error: Error code (one of the ERROR_* constants)
        required_input: For invalid_input - list of required covered components
        supported_algorithms: For unsupported_algorithm - list of supported algorithms

    Returns:
        AAuth-Error header value

    Examples:
        build_aauth_error("invalid_signature")
        -> 'error=invalid_signature'

        build_aauth_error("invalid_input", required_input=["@method", "@authority", "@path", "signature-key"])
        -> 'error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key")'

        build_aauth_error("unsupported_algorithm", supported_algorithms=["EdDSA", "ES256"])
        -> 'error=unsupported_algorithm, supported_algorithms=("EdDSA" "ES256")'
    """
    parts = [f"error={error}"]

    if required_input and error == ERROR_INVALID_INPUT:
        inner = " ".join(f'"{c}"' for c in required_input)
        parts.append(f"required_input=({inner})")

    if supported_algorithms and error == ERROR_UNSUPPORTED_ALGORITHM:
        inner = " ".join(f'"{a}"' for a in supported_algorithms)
        parts.append(f"supported_algorithms=({inner})")

    return ", ".join(parts)


def parse_aauth_error(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Error header value.

    Args:
        header_value: AAuth-Error header value

    Returns:
        Dictionary with:
        - error: str (error code)
        - required_input: Optional[List[str]]
        - supported_algorithms: Optional[List[str]]
    """
    result: Dict[str, Any] = {
        "error": None,
        "required_input": None,
        "supported_algorithms": None,
    }

    # Extract error code
    error_match = re.search(r'error=([\w_]+)', header_value)
    if error_match:
        result["error"] = error_match.group(1)

    # Extract inner list parameters
    for param_name in ("required_input", "supported_algorithms"):
        list_match = re.search(rf'{param_name}=\(([^)]+)\)', header_value)
        if list_match:
            inner = list_match.group(1)
            result[param_name] = re.findall(r'"([^"]+)"', inner)

    return result


# --- Backward compatibility aliases ---
# Map old API names to new AAuth-Requirement API

def parse_aauth_header(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Requirement header (backward-compatible name).

    Accepts both old 'require=' and new 'requirement=' formats.
    """
    # Support both old and new parameter names
    if "requirement=" in header_value:
        parsed = parse_aauth_requirement(header_value)
        parsed["require"] = parsed["requirement"]
        return parsed
    elif "require=" in header_value:
        # Old format compatibility
        result = {
            "requirement": None,
            "require": None,
            "resource_token": None,
            "auth_server": None,
            "url": None,
            "code": None,
        }
        require_match = re.search(r'require=([\w-]+)', header_value)
        if require_match:
            result["requirement"] = require_match.group(1)
            result["require"] = require_match.group(1)

        rt_match = re.search(r'resource-token="([^"]+)"', header_value)
        if rt_match:
            result["resource_token"] = rt_match.group(1)

        as_match = re.search(r'auth-server="([^"]+)"', header_value)
        if as_match:
            result["auth_server"] = as_match.group(1)

        url_match = re.search(r'url="([^"]+)"', header_value)
        if url_match:
            result["url"] = url_match.group(1)

        code_match = re.search(r'code="([^"]+)"', header_value)
        if code_match:
            result["code"] = code_match.group(1)

        return result
    else:
        raise ChallengeError("AAuth header must include 'requirement' or 'require' parameter")


# Old function name aliases
build_pseudonym_challenge = build_pseudonym_requirement
build_identity_challenge = build_identity_requirement
build_auth_token_challenge = build_auth_token_requirement
build_approval_challenge = build_approval_requirement


def build_interaction_challenge(code: str, url: Optional[str] = None) -> str:
    """Build interaction requirement (backward-compatible signature).

    Args:
        code: Interaction code
        url: Interaction URL (required in new spec)
    """
    if url:
        return build_interaction_requirement(url, code)
    return f'requirement=interaction; code="{code}"'


def build_agent_auth_challenge(
    require_signature: bool = True,
    require_identity: bool = False,
    require_auth_token: bool = False,
    resource_token: Optional[str] = None,
    auth_server: Optional[str] = None,
    **kwargs
) -> str:
    """Build AAuth-Requirement header (backward-compatible API).

    Maps old Agent-Auth parameters to new AAuth-Requirement header format.
    """
    if require_auth_token and resource_token and auth_server:
        return build_auth_token_requirement(resource_token, auth_server)
    elif require_identity:
        return build_identity_requirement()
    else:
        return build_pseudonym_requirement()


def parse_agent_auth_header(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Requirement header with backward-compatible result format.

    Returns dict compatible with old Agent-Auth parser.
    """
    parsed = parse_aauth_header(header_value)

    result = {
        "httpsig": True,
        "identity": parsed["requirement"] == REQUIRE_IDENTITY,
        "auth_token": parsed["requirement"] == REQUIRE_AUTH_TOKEN,
        "resource_token": parsed.get("resource_token"),
        "auth_server": parsed.get("auth_server"),
        "require": parsed["requirement"],
        "requirement": parsed["requirement"],
        "url": parsed.get("url"),
        "code": parsed.get("code"),
    }
    return result
