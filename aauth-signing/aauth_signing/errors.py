"""Exceptions shared by the aauth-signing package."""

# Signature-Error header codes (401 responses, per draft-hardt-httpbis-signature-key)
ERROR_INVALID_SIGNATURE = "invalid_signature"


class AAuthError(Exception):
    """Base exception for AAuth-related errors in this package."""

    pass


class SignatureError(AAuthError):
    """HTTP signature validation or creation error."""

    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code or ERROR_INVALID_SIGNATURE
        self.details = details or {}


class TokenError(AAuthError):
    """Token validation or creation error."""

    def __init__(self, message: str, token_type: str = None, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.token_type = token_type
        self.error_code = error_code
        self.details = details or {}
