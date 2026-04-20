"""Custom exceptions and error codes for AAuth."""

from aauth_signing.errors import (
    AAuthError,
    SignatureError,
    TokenError,
    ERROR_INVALID_SIGNATURE,
)


# --- Signature-Error Header Codes (401 responses, per draft-hardt-httpbis-signature-key) ---

ERROR_INVALID_REQUEST = "invalid_request"
ERROR_INVALID_INPUT = "invalid_input"
# ERROR_INVALID_SIGNATURE imported from aauth_signing.errors
ERROR_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
ERROR_INVALID_KEY = "invalid_key"
ERROR_UNKNOWN_KEY = "unknown_key"
ERROR_INVALID_JWT = "invalid_jwt"
ERROR_EXPIRED_JWT = "expired_jwt"

# --- Token Endpoint Error Codes (JSON body, per draft-hardt-aauth-protocol) ---

ERROR_INVALID_AGENT_TOKEN = "invalid_agent_token"
ERROR_EXPIRED_AGENT_TOKEN = "expired_agent_token"
ERROR_INVALID_RESOURCE_TOKEN = "invalid_resource_token"
ERROR_EXPIRED_RESOURCE_TOKEN = "expired_resource_token"
ERROR_INVALID_AUTH_TOKEN = "invalid_auth_token"
ERROR_SERVER_ERROR = "server_error"

# --- Interaction / Authorization Error Codes ---

# 403: User interaction needed but no interaction channel available (agent lacks
# 'interaction' capability and PS cannot reach the user out-of-band).
ERROR_INTERACTION_REQUIRED = "interaction_required"

# --- Mission Status Error Codes (JSON body, per draft-hardt-aauth-protocol) ---

# Missions have two states: active or terminated (no suspended state).
ERROR_MISSION_TERMINATED = "mission_terminated"

# --- Polling Error Codes (JSON body, per draft-hardt-aauth-protocol) ---

ERROR_DENIED = "denied"
ERROR_ABANDONED = "abandoned"
ERROR_EXPIRED = "expired"
ERROR_INVALID_CODE = "invalid_code"
ERROR_SLOW_DOWN = "slow_down"

# Removed from spec:
# ERROR_KEY_BINDING_FAILED - no longer a separate error code


def build_error_response(error: str, description: str = None, **extras) -> dict:
    """Build a standard AAuth token endpoint error response body (JSON).

    For authentication errors (401), use build_aauth_error() in aauth_header.py
    to construct the Signature-Error header instead.

    Args:
        error: Error code (one of the token endpoint or polling ERROR_* constants)
        description: Human-readable error description
        **extras: Additional fields

    Returns:
        Error response dictionary
    """
    response = {"error": error}
    if description:
        response["error_description"] = description
    response.update(extras)
    return response


class ChallengeError(AAuthError):
    """Signature-Requirement parsing or building error."""

    def __init__(self, message: str, challenge_type: str = None, details: dict = None):
        super().__init__(message)
        self.challenge_type = challenge_type
        self.details = details or {}


class MetadataError(AAuthError):
    """Metadata discovery or parsing error."""

    def __init__(self, message: str, metadata_url: str = None, details: dict = None):
        super().__init__(message)
        self.metadata_url = metadata_url
        self.details = details or {}


class JWKSError(AAuthError):
    """JWKS fetching or parsing error."""

    def __init__(self, message: str, jwks_uri: str = None, details: dict = None):
        super().__init__(message)
        self.jwks_uri = jwks_uri
        self.details = details or {}
