"""Custom exceptions for AAuth."""


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
    """Agent-Auth challenge parsing or building error."""
    
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

