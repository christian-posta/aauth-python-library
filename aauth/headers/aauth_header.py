"""Signature-Requirement and Signature-Error HTTP response header parsing and building.

Per draft-hardt-httpbis-signature-key, the Signature-Requirement header is a
Structured Fields Dictionary (RFC 8941) with a `requirement` key indicating
the requirement level. The Signature-Error header is a Structured Fields
Dictionary with an `error` key indicating the error code.

Base requirement levels (pseudonym, identity) are defined in the Signature-Key spec.
Additional levels (auth-token, interaction, approval) are registered by the AAuth
protocol spec (draft-hardt-aauth-protocol).
"""

import re
from typing import Dict, Any, Optional, List, Mapping, Union
from ..errors import ChallengeError


# Requirement levels (base: pseudonym, identity from Signature-Key spec)
# (extended: auth-token, interaction, approval from AAuth protocol spec)
REQUIRE_PSEUDONYM = "pseudonym"
REQUIRE_IDENTITY = "identity"
REQUIRE_AUTH_TOKEN = "auth-token"
REQUIRE_INTERACTION = "interaction"
REQUIRE_APPROVAL = "approval"
REQUIRE_CLARIFICATION = "clarification"
REQUIRE_CLAIMS = "claims"

# HTTP header field names (spec: Signature-Key draft + AAuth protocol)
HEADER_SIGNATURE_REQUIREMENT = "Signature-Requirement"
HEADER_AAUTH_REQUIREMENT = "AAuth-Requirement"
HEADER_SIGNATURE_ERROR = "Signature-Error"

# Signature-Error codes (from draft-hardt-httpbis-signature-key)
ERROR_INVALID_REQUEST = "invalid_request"
ERROR_INVALID_INPUT = "invalid_input"
ERROR_INVALID_SIGNATURE = "invalid_signature"
ERROR_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
ERROR_INVALID_KEY = "invalid_key"
ERROR_UNKNOWN_KEY = "unknown_key"
ERROR_INVALID_JWT = "invalid_jwt"
ERROR_EXPIRED_JWT = "expired_jwt"


def parse_signature_requirement(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Requirement response header.

    Formats:
        Signature-Requirement: requirement=pseudonym
        Signature-Requirement: requirement=identity
        Signature-Requirement: requirement=identity, algorithms=("EdDSA" "ES256")
        Signature-Requirement: requirement=auth-token; resource-token="..."
        Signature-Requirement: requirement=interaction; url="..."; code="ABCD1234"
        Signature-Requirement: requirement=approval

    Args:
        header_value: Signature-Requirement header value

    Returns:
        Dictionary with:
        - requirement: str
        - resource_token: Optional[str]
        - url: Optional[str]
        - code: Optional[str]
        - algorithms: Optional[List[str]]
        - required_input: Optional[List[str]]

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
            "algorithms": None,
            "required_input": None,
        }

        # Extract requirement value
        require_match = re.search(r'requirement=([\w-]+)', header_value)
        if not require_match:
            raise ChallengeError("Signature-Requirement header must include 'requirement' parameter")

        result["requirement"] = require_match.group(1)

        # Extract resource-token parameter
        rt_match = re.search(r'resource-token="([^"]+)"', header_value)
        if rt_match:
            result["resource_token"] = rt_match.group(1)

        # Extract auth-server parameter (backward compat)
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

        # Extract inner list parameters (algorithms, required_input)
        for param_name in ("algorithms", "required_input"):
            list_match = re.search(rf'{param_name}=\(([^)]+)\)', header_value)
            if list_match:
                inner = list_match.group(1)
                result[param_name] = re.findall(r'"([^"]+)"', inner)

        return result

    except ChallengeError:
        raise
    except Exception as e:
        raise ChallengeError(f"Failed to parse Signature-Requirement header: {e}") from e


def build_pseudonym_requirement(
    algorithms: Optional[List[str]] = None,
    required_input: Optional[List[str]] = None,
) -> str:
    """Build Signature-Requirement requiring pseudonymous signature.

    Args:
        algorithms: Optional list of acceptable signing algorithms
        required_input: Optional list of required covered components

    Returns:
        Signature-Requirement header value
    """
    parts = ["requirement=pseudonym"]
    if algorithms:
        inner = " ".join(f'"{a}"' for a in algorithms)
        parts.append(f"algorithms=({inner})")
    if required_input:
        inner = " ".join(f'"{c}"' for c in required_input)
        parts.append(f"required_input=({inner})")
    return ", ".join(parts)


def build_identity_requirement(
    algorithms: Optional[List[str]] = None,
    required_input: Optional[List[str]] = None,
) -> str:
    """Build Signature-Requirement requiring verified agent identity.

    Args:
        algorithms: Optional list of acceptable signing algorithms
        required_input: Optional list of required covered components

    Returns:
        Signature-Requirement header value
    """
    parts = ["requirement=identity"]
    if algorithms:
        inner = " ".join(f'"{a}"' for a in algorithms)
        parts.append(f"algorithms=({inner})")
    if required_input:
        inner = " ".join(f'"{c}"' for c in required_input)
        parts.append(f"required_input=({inner})")
    return ", ".join(parts)


def build_auth_token_requirement(
    resource_token: str,
    auth_server: str = None,
) -> str:
    """Build AAuth-Requirement value requiring an auth token (use header AAuth-Requirement).

    Per spec, the auth server is discovered from the resource token's aud claim.

    Args:
        resource_token: Resource token JWT string
        auth_server: Deprecated - auth server discovered from resource token aud

    Returns:
        Header *value* for ``AAuth-Requirement`` with resource-token
    """
    return f'requirement=auth-token; resource-token="{resource_token}"'


def build_interaction_requirement(url: str, code: str) -> str:
    """Build AAuth-Requirement value for user interaction (use header AAuth-Requirement).

    Args:
        url: Interaction URL (HTTPS, no query or fragment)
        code: Interaction code (short alphanumeric)

    Returns:
        Header *value* for ``AAuth-Requirement``
    """
    return f'requirement=interaction; url="{url}"; code="{code}"'


def build_approval_requirement() -> str:
    """Build AAuth-Requirement value for approval pending."""
    return "requirement=approval"


def build_clarification_requirement() -> str:
    """Build AAuth-Requirement value for clarification (body carries question)."""
    return "requirement=clarification"


def build_claims_requirement() -> str:
    """Build AAuth-Requirement value for claims (body carries required_claims)."""
    return "requirement=claims"


def build_aauth_mission_header(manager: str, s256: str) -> str:
    """Build ``AAuth-Mission`` request header value (spec Section 8.2)."""
    return f'manager="{manager}"; s256="{s256}"'


def parse_aauth_mission_header(header_value: str) -> Dict[str, Optional[str]]:
    """Parse ``AAuth-Mission`` header into manager URL and s256 hash."""
    result: Dict[str, Optional[str]] = {"manager": None, "s256": None}
    m = re.search(r'manager="([^"]+)"', header_value)
    if m:
        result["manager"] = m.group(1)
    s = re.search(r's256="([^"]+)"', header_value)
    if s:
        result["s256"] = s.group(1)
    return result


def aauth_protocol_requirement_levels() -> frozenset:
    """Requirement levels that MUST use the ``AAuth-Requirement`` response header."""
    return frozenset(
        {
            REQUIRE_AUTH_TOKEN,
            REQUIRE_INTERACTION,
            REQUIRE_APPROVAL,
            REQUIRE_CLARIFICATION,
            REQUIRE_CLAIMS,
        }
    )


def requirement_header_for_level(requirement_level: str) -> str:
    """Return the correct response header name for a requirement level."""
    if requirement_level in (REQUIRE_PSEUDONYM, REQUIRE_IDENTITY):
        return HEADER_SIGNATURE_REQUIREMENT
    return HEADER_AAUTH_REQUIREMENT


def get_challenge_header_value(headers: Union[Mapping[str, Any], None]) -> str:
    """Extract requirement header value from a mapping of HTTP response headers.

    Checks ``AAuth-Requirement``, ``Signature-Requirement``, and legacy ``AAuth`` /
    ``Agent-Auth``. Keys are matched case-insensitively.
    """
    if headers is None:
        return ""
    if not hasattr(headers, "items"):
        return ""
    # Case-insensitive lookup (httpx uses lowercased keys)
    lower = {str(k).lower(): v for k, v in headers.items()}
    return (
        lower.get("aauth-requirement", "")
        or lower.get("signature-requirement", "")
        or lower.get("aauth", "")
        or lower.get("agent-auth", "")
    )


# --- Signature-Error header ---

def build_signature_error(
    error: str,
    required_input: Optional[List[str]] = None,
    supported_algorithms: Optional[List[str]] = None,
) -> str:
    """Build Signature-Error header value per draft-hardt-httpbis-signature-key.

    Args:
        error: Error code (one of the ERROR_* constants)
        required_input: For invalid_input - list of required covered components
        supported_algorithms: For unsupported_algorithm - list of supported algorithms

    Returns:
        Signature-Error header value
    """
    parts = [f"error={error}"]

    if required_input and error == ERROR_INVALID_INPUT:
        inner = " ".join(f'"{c}"' for c in required_input)
        parts.append(f"required_input=({inner})")

    if supported_algorithms and error == ERROR_UNSUPPORTED_ALGORITHM:
        inner = " ".join(f'"{a}"' for a in supported_algorithms)
        parts.append(f"supported_algorithms=({inner})")

    return ", ".join(parts)


def parse_signature_error(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Error header value.

    Args:
        header_value: Signature-Error header value

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

    error_match = re.search(r'error=([\w_]+)', header_value)
    if error_match:
        result["error"] = error_match.group(1)

    for param_name in ("required_input", "supported_algorithms"):
        list_match = re.search(rf'{param_name}=\(([^)]+)\)', header_value)
        if list_match:
            inner = list_match.group(1)
            result[param_name] = re.findall(r'"([^"]+)"', inner)

    return result


# --- Backward compatibility aliases ---

# Old name aliases
parse_aauth_requirement = parse_signature_requirement
parse_aauth_error = parse_signature_error
build_aauth_error = build_signature_error
build_pseudonym_challenge = build_pseudonym_requirement
build_identity_challenge = build_identity_requirement
build_auth_token_challenge = build_auth_token_requirement
build_approval_challenge = build_approval_requirement


def build_interaction_challenge(code: str, url: Optional[str] = None) -> str:
    """Build interaction requirement (backward-compatible signature)."""
    if url:
        return build_interaction_requirement(url, code)
    return f'requirement=interaction; code="{code}"'


def parse_aauth_header(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Requirement header (backward-compatible name).

    Accepts old 'require=', 'requirement=' formats.
    """
    if "requirement=" in header_value:
        parsed = parse_signature_requirement(header_value)
        parsed["require"] = parsed["requirement"]
        return parsed
    elif "require=" in header_value:
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
        raise ChallengeError("Header must include 'requirement' or 'require' parameter")


def build_agent_auth_challenge(
    require_signature: bool = True,
    require_identity: bool = False,
    require_auth_token: bool = False,
    resource_token: Optional[str] = None,
    auth_server: Optional[str] = None,
    **kwargs
) -> str:
    """Build Signature-Requirement header (backward-compatible API)."""
    if require_auth_token and resource_token and auth_server:
        return build_auth_token_requirement(resource_token, auth_server)
    elif require_identity:
        return build_identity_requirement()
    else:
        return build_pseudonym_requirement()


def parse_agent_auth_header(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Requirement header with backward-compatible result format."""
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
