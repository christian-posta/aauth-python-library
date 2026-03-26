"""Custom exceptions and error codes for AAuth."""


# --- Authentication Error Codes (401 responses) ---

ERROR_INVALID_SIGNATURE = "invalid_signature"
ERROR_INVALID_AGENT_TOKEN = "invalid_agent_token"
ERROR_INVALID_RESOURCE_TOKEN = "invalid_resource_token"
ERROR_INVALID_AUTH_TOKEN = "invalid_auth_token"
ERROR_KEY_BINDING_FAILED = "key_binding_failed"

# --- Token Endpoint Error Codes ---

ERROR_INVALID_REQUEST = "invalid_request"
ERROR_SERVER_ERROR = "server_error"

# --- Polling Error Codes ---

ERROR_DENIED = "denied"
ERROR_ABANDONED = "abandoned"
ERROR_EXPIRED = "expired"
ERROR_INVALID_CODE = "invalid_code"


def build_error_response(error: str, description: str = None, **extras) -> dict:
    """Build a standard AAuth error response body.

    Args:
        error: Error code (one of the ERROR_* constants)
        description: Human-readable error description
        **extras: Additional fields (e.g., required_components)

    Returns:
        Error response dictionary
    """
    response = {"error": error}
    if description:
        response["error_description"] = description
    response.update(extras)
    return response


class AAuthError(Exception):
    """Base exception for all AAuth errors."""
    pass


class SignatureError(AAuthError):
    """HTTP signature validation or creation error."""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.details = details or {}


class TokenError(AAuthError):
    """Token validation or creation error."""

    def __init__(self, message: str, token_type: str = None, details: dict = None):
        super().__init__(message)
        self.token_type = token_type
        self.details = details or {}


class ChallengeError(AAuthError):
    """AAuth challenge parsing or building error."""

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
