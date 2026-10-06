"""AAuth and Signature-Key HTTP header parsing and building.

Per draft-hardt-httpbis-signature-key:
- ``Accept-Signature`` is the response header resources use to declare they accept
  HTTP Message Signatures. It replaces the old ``Signature-Requirement`` header for
  pseudonym and identity requirement levels.
  Format: ``sig=("@method" "@authority" "@path");sigkey=<type>``
  where ``sigkey=jkt`` (pseudonym/hwk) or ``sigkey=uri`` (identity/jwks_uri).
- ``Signature-Error`` conveys signature validation failures.

Per draft-hardt-aauth-protocol:
- ``AAuth-Requirement`` conveys AAuth-specific requirements (auth-token, interaction,
  approval, clarification, claims). These remain unchanged.
"""

import re
from typing import Dict, Any, Optional, List, Mapping, Union
from ..errors import ChallengeError


# Requirement levels (base: pseudonym, identity from Signature-Key spec)
# (extended: auth-token, interaction, approval from AAuth protocol spec)
REQUIRE_PSEUDONYM = "pseudonym"
REQUIRE_IDENTITY = "identity"
REQUIRE_AGENT_TOKEN = "agent-token"
REQUIRE_PERSON_TOKEN = "person-token"
REQUIRE_AUTH_TOKEN = "auth-token"
REQUIRE_INTERACTION = "interaction"
REQUIRE_APPROVAL = "approval"
REQUIRE_CLARIFICATION = "clarification"
REQUIRE_CLAIMS = "claims"

# HTTP header field names (spec: Signature-Key draft + AAuth protocol)
HEADER_ACCEPT_SIGNATURE = (
    "Accept-Signature"  # Replaces Signature-Requirement for pseudonym/identity
)
HEADER_SIGNATURE_REQUIREMENT = (
    "Signature-Requirement"  # Deprecated — use HEADER_ACCEPT_SIGNATURE
)
HEADER_AAUTH_REQUIREMENT = "AAuth-Requirement"
HEADER_AAUTH_ACCESS = "AAuth-Access"
HEADER_AAUTH_CAPABILITIES = "AAuth-Capabilities"
HEADER_SIGNATURE_ERROR = "Signature-Error"

# Accept-Signature sigkey types (draft-hardt-httpbis-signature-key §4.1)
SIGKEY_JKT = "jkt"  # Pseudonym: inline public key / JWK thumbprint (hwk, jkt-jwt)
SIGKEY_URI = "uri"  # Identity: URI-identified key (jwks_uri, jwt, x509 with URI SAN)
SIGKEY_X509 = "x509"  # PKI: X.509 certificate chain (x509)

# Default covered components for Accept-Signature
_DEFAULT_COMPONENTS = ["@method", "@authority", "@path"]

# AAuth-Capabilities values (agent declares what interaction channels it supports)
CAPABILITY_INTERACTION = "interaction"
CAPABILITY_CLARIFICATION = "clarification"
CAPABILITY_PAYMENT = "payment"

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
    import http_sfv

    try:
        fields = http_sfv.Dictionary()
        fields.parse(header_value.encode("ascii"))
        item = fields["requirement"]
        if not isinstance(item.value, http_sfv.Token):
            raise ValueError("requirement must be a token")
        p = dict(item.params)
        return {
            "requirement": str(item.value),
            "resource_token": p.get("resource-token"),
            "auth_server": p.get("auth-server"),
            "url": p.get("url"),
            "code": p.get("code"),
            "algorithms": None,
            "required_input": None,
        }
    except Exception as exc:
        raise ChallengeError("Invalid AAuth-Requirement structured dictionary") from exc


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


def build_accept_signature(
    sigkey: str = SIGKEY_URI,
    components: Optional[List[str]] = None,
    algs: Optional[List[str]] = None,
) -> str:
    """Build ``Accept-Signature`` header value per draft-hardt-httpbis-signature-key.

    Resources return this header to declare they accept HTTP Message Signatures.
    Replaces the old ``Signature-Requirement: requirement=pseudonym/identity`` format.

    Args:
        sigkey: Key discovery type — ``"jkt"`` for pseudonym, ``"uri"`` for
                identity, ``"x509"`` for PKI certificate.
        components: Covered component identifiers. Defaults to
                    ``["@method", "@authority", "@path"]``.
        algs: Optional list of acceptable signing algorithms (RFC 9421 identifiers).

    Returns:
        ``Accept-Signature`` header value, e.g.
        ``sig=("@method" "@authority" "@path");sigkey=uri``
        or with algs:
        ``sig=("@method" "@authority" "@path");alg="ecdsa-p256-sha256";sigkey=uri``
    """
    comps = components or _DEFAULT_COMPONENTS
    inner = " ".join(f'"{c}"' for c in comps)
    params = f"sigkey={sigkey}"
    if algs and len(algs) == 1:
        # Single algorithm uses alg parameter
        params = f'alg="{algs[0]}";{params}'
    return f"sig=({inner});{params}"


def parse_accept_signature(header_value: str) -> Dict[str, Any]:
    """Parse ``Accept-Signature`` header value.

    Returns a dict with:
    - ``sigkey``: ``"jkt"``, ``"uri"``, ``"x509"``, or whatever sigkey value is present
    - ``components``: list of covered component strings
    - ``alg``: optional single algorithm string
    - ``requirement``: mapped requirement level for compatibility with challenge handler
    """
    result: Dict[str, Any] = {
        "sigkey": None,
        "components": [],
        "alg": None,
        "requirement": None,
    }
    # Extract sigkey parameter
    sk_match = re.search(r"sigkey=([^\s;,]+)", header_value)
    if sk_match:
        result["sigkey"] = sk_match.group(1)
        # Map sigkey to requirement level for challenge handler compatibility
        if result["sigkey"] == SIGKEY_JKT:
            result["requirement"] = REQUIRE_PSEUDONYM
        elif result["sigkey"] == SIGKEY_URI:
            result["requirement"] = REQUIRE_IDENTITY
        elif result["sigkey"] == SIGKEY_X509:
            result["requirement"] = REQUIRE_IDENTITY  # x509 is identity-level
    # Extract alg parameter
    alg_match = re.search(r'alg="([^"]+)"', header_value)
    if alg_match:
        result["alg"] = alg_match.group(1)
    # Extract inner list of components from sig=(...)
    comp_match = re.search(r"sig=\(([^)]*)\)", header_value)
    if comp_match:
        result["components"] = re.findall(r'"([^"]+)"', comp_match.group(1))
    return result


def build_aauth_capabilities_header(capabilities: List[str]) -> str:
    """Build ``AAuth-Capabilities`` request header value.

    The agent declares what interaction channels it supports so the PS/resource
    knows which channels are available to reach the user.

    Args:
        capabilities: List of capability tokens, e.g. ["interaction", "clarification"]

    Returns:
        Header value string, e.g. ``interaction, clarification``
    """
    return ", ".join(capabilities)


def parse_aauth_capabilities_header(header_value: str) -> List[str]:
    """Parse ``AAuth-Capabilities`` header into a list of capability tokens."""
    return [c.strip() for c in header_value.split(",") if c.strip()]


def _validate_token68(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value):
        raise ChallengeError(
            "Invalid session token: expected exactly one token68 credential"
        )
    return value


def build_aauth_access_header(token: str) -> str:
    return _validate_token68(token)


def parse_authorization_aauth_header(header_value: str) -> Optional[str]:
    if not header_value:
        return None
    scheme, sep, value = header_value.partition(" ")
    if scheme.lower() != "aauth":
        return None
    if not sep:
        raise ChallengeError("Missing session credential")
    return _validate_token68(value)


def build_aauth_mission_header(approver: str, s256: str) -> str:
    raise ChallengeError(
        "AAuth-Mission was removed in draft -11; use mission_s256 in person-token requests"
    )


def parse_aauth_mission_header(header_value: str) -> Dict[str, Optional[str]]:
    """Parse ``AAuth-Mission`` header into approver URL and s256 hash."""
    result: Dict[str, Optional[str]] = {"approver": None, "s256": None}
    # Support both new "approver=" and old "manager=" for backward compatibility
    m = re.search(r'approver="([^"]+)"', header_value) or re.search(
        r'manager="([^"]+)"', header_value
    )
    if m:
        result["approver"] = m.group(1)
    s = re.search(r's256="([^"]+)"', header_value)
    if s:
        result["s256"] = s.group(1)
    return result


def aauth_protocol_requirement_levels() -> frozenset:
    """Requirement levels that MUST use the ``AAuth-Requirement`` response header."""
    return frozenset(
        {
            REQUIRE_AGENT_TOKEN,
            REQUIRE_PERSON_TOKEN,
            REQUIRE_AUTH_TOKEN,
            REQUIRE_INTERACTION,
            REQUIRE_APPROVAL,
            REQUIRE_CLARIFICATION,
            REQUIRE_CLAIMS,
        }
    )


def requirement_header_for_level(requirement_level: str) -> str:
    """Return the correct response header name for a requirement level.

    Per updated spec, pseudonym and identity levels use ``Accept-Signature``
    (from draft-hardt-httpbis-signature-key). All AAuth-specific levels use
    ``AAuth-Requirement``.
    """
    if requirement_level in (REQUIRE_PSEUDONYM, REQUIRE_IDENTITY):
        return HEADER_ACCEPT_SIGNATURE
    return HEADER_AAUTH_REQUIREMENT


def get_challenge_header_value(headers: Union[Mapping[str, Any], None]) -> str:
    """Extract requirement header value from a mapping of HTTP response headers.

    Checks ``AAuth-Requirement``, ``Accept-Signature``, ``Signature-Requirement``
    (deprecated), and legacy ``AAuth`` / ``Agent-Auth``. Keys are matched
    case-insensitively.

    ``AAuth-Requirement`` takes priority (covers auth-token, interaction, approval,
    clarification, claims). ``Accept-Signature`` is checked next (pseudonym/identity).
    """
    if headers is None:
        return ""
    if not hasattr(headers, "items"):
        return ""
    # Case-insensitive lookup (httpx uses lowercased keys)
    lower = {str(k).lower(): v for k, v in headers.items()}
    return (
        lower.get("aauth-requirement", "")
        or lower.get("accept-signature", "")
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

    error_match = re.search(r"error=([\w_]+)", header_value)
    if error_match:
        result["error"] = error_match.group(1)

    for param_name in ("required_input", "supported_algorithms"):
        list_match = re.search(rf"{param_name}=\(([^)]+)\)", header_value)
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
    """Parse AAuth challenge header (handles all formats).

    Accepts:
    - Accept-Signature format: ``sig=("@method" ...);sigkey=jkt``
    - AAuth-Requirement format: ``requirement=auth-token; resource-token="..."``
    - Legacy Signature-Requirement: ``requirement=pseudonym``
    - Legacy require= format: ``require=identity``
    """
    # Detect Accept-Signature format (contains "sig=" or "sigkey=")
    if "sigkey=" in header_value or re.match(r"\s*sig\d*=\(", header_value):
        parsed = parse_accept_signature(header_value)
        return {
            "requirement": parsed["requirement"],
            "require": parsed["requirement"],
            "resource_token": None,
            "auth_server": None,
            "url": None,
            "code": None,
            "sigkey": parsed["sigkey"],
            "components": parsed["components"],
            "alg": parsed.get("alg"),
        }

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
        require_match = re.search(r"require=([\w-]+)", header_value)
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
        raise ChallengeError(
            "Header must include 'requirement', 'require', or 'sigkey' parameter"
        )


def build_agent_auth_challenge(
    require_signature: bool = True,
    require_identity: bool = False,
    require_auth_token: bool = False,
    resource_token: Optional[str] = None,
    auth_server: Optional[str] = None,
    **kwargs,
) -> str:
    """Build Signature-Requirement header (backward-compatible API)."""
    if require_auth_token and resource_token:
        return build_auth_token_requirement(resource_token, auth_server)
    elif require_identity:
        return build_agent_token_requirement()
    elif require_auth_token:
        return build_person_token_requirement()
    else:
        return build_agent_token_requirement()


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


def build_agent_token_requirement():
    return "requirement=agent-token"


def build_person_token_requirement():
    return "requirement=person-token"
