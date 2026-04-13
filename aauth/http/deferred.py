"""Deferred response handling for AAuth.

Per spec Section 10, any endpoint may return 202 Accepted with a Location header
to indicate the request is pending. The agent polls the Location URL with GET
until a terminal response is received.
"""

import uuid
import string
import random
from typing import Dict, Any, Optional, List

from ..headers.aauth_header import HEADER_AAUTH_REQUIREMENT


def generate_pending_id() -> str:
    """Generate a unique pending request ID for use in Location URLs."""
    return uuid.uuid4().hex[:12]


def generate_interaction_code(length: int = 8) -> str:
    """Generate an interaction code per spec Section 19.11.

    Codes use unreserved URI characters (RFC 3986 Section 2.3):
    A-Z a-z 0-9 (excluding - . _ ~ for readability).

    Args:
        length: Code length (default: 8)

    Returns:
        Alphanumeric interaction code (e.g., "ABCD1234")
    """
    # Use uppercase + digits for readability (spec examples use this pattern)
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))


def build_pending_response_body(
    location: str,
    require: Optional[str] = None,
    code: Optional[str] = None,
    clarification: Optional[str] = None,
    status: str = "pending",
    required_claims: Optional[List[str]] = None,
    clarification_timeout: Optional[int] = None,
    clarification_options: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build the JSON body for a 202 Accepted pending response.

    Args:
        location: The pending URL (echoes Location header)
        require: Requirement level ("interaction" or "approval")
        code: Interaction code (required when require="interaction")
        clarification: User's question during clarification chat
        status: Status string - "pending" or "interacting" (user arrived at interaction endpoint)

    Returns:
        Response body dictionary
    """
    body = {
        "status": status,
        "location": location,
    }
    if require:
        body["requirement"] = require
    if code:
        body["code"] = code
    if clarification:
        body["clarification"] = clarification
    if required_claims:
        body["required_claims"] = required_claims
    if clarification_timeout is not None:
        body["timeout"] = clarification_timeout
    if clarification_options:
        body["options"] = clarification_options
    return body


def build_pending_response_headers(
    location: str,
    retry_after: int = 0,
    require: Optional[str] = None,
    code: Optional[str] = None,
    url: Optional[str] = None,
    required_claims: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Build response headers for a 202 Accepted pending response.

    Args:
        location: The pending URL
        retry_after: Seconds before agent should poll (default: 0)
        require: Requirement level for AAuth header
        code: Interaction code for AAuth header
        url: Interaction URL (REQUIRED when require="interaction" per spec Section 6.2)

    Returns:
        Headers dictionary
    """
    headers = {
        "Location": location,
        "Retry-After": str(retry_after),
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
    }

    # Build AAuth-Requirement header if needed (protocol-level deferred requirements)
    if require == "interaction" and code and url:
        headers[HEADER_AAUTH_REQUIREMENT] = f'requirement=interaction; url="{url}"; code="{code}"'
    elif require == "approval":
        headers[HEADER_AAUTH_REQUIREMENT] = "requirement=approval"
    elif require == "claims" and required_claims:
        inner = " ".join(f'"{c}"' for c in required_claims)
        headers[HEADER_AAUTH_REQUIREMENT] = f"requirement=claims; required_claims=({inner})"

    return headers


def build_success_response(auth_token: str, expires_in: int = 3600) -> Dict[str, Any]:
    """Build the JSON body for a successful token response (200 OK).

    Args:
        auth_token: The issued auth token JWT
        expires_in: Token lifetime in seconds

    Returns:
        Response body dictionary
    """
    return {
        "auth_token": auth_token,
        "expires_in": expires_in,
    }


def build_polling_error_body(error: str, description: Optional[str] = None) -> Dict[str, Any]:
    """Build error response body for terminal polling responses.

    Args:
        error: Error code (denied, abandoned, expired, invalid_code, server_error)
        description: Human-readable description

    Returns:
        Error response body
    """
    body = {"error": error}
    if description:
        body["error_description"] = description
    return body


def parse_pending_response(body: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a pending response body from a server.

    Per spec, status can be "pending" or "interacting" (user arrived at interaction
    endpoint). Agents MUST treat unrecognized status values as "pending".

    Args:
        body: Response JSON body

    Returns:
        Parsed response with keys: status, requirement, code, clarification, location
    """
    status = body.get("status", "pending")
    if status not in ("pending", "interacting"):
        status = "pending"
    return {
        "status": status,
        "location": body.get("location"),
        "requirement": body.get("requirement") or body.get("require"),
        "code": body.get("code"),
        "clarification": body.get("clarification"),
    }


def is_pending_response(status_code: int) -> bool:
    """Check if an HTTP response indicates a pending/deferred state."""
    return status_code == 202


# --- Token endpoint request mode detection ---

def detect_token_request_mode(params: Dict[str, Any]) -> str:
    """Detect token endpoint mode from request parameters.

    Per spec Section 11.1:
    - resource_token present → "resource_access"
    - scope present (no resource_token) → "self_access"
    - resource_token + upstream_token → "call_chaining"
    - auth_token present → "token_refresh"

    Args:
        params: Request parameters dictionary

    Returns:
        Mode string: "resource_access", "self_access", "call_chaining", "token_refresh"

    Raises:
        ValueError: If parameters don't match any known mode
    """
    has_resource_token = "resource_token" in params and params["resource_token"]
    has_upstream_token = "upstream_token" in params and params["upstream_token"]
    has_scope = "scope" in params and params["scope"]
    has_auth_token = "auth_token" in params and params["auth_token"]

    if has_auth_token:
        return "token_refresh"
    if has_resource_token and has_upstream_token:
        return "call_chaining"
    if has_resource_token:
        return "resource_access"
    if has_scope:
        return "self_access"

    raise ValueError("Request parameters don't match any known token endpoint mode")
