"""Framework-agnostic HTTP response representation for AAuth."""

from typing import Dict, Optional


class AAuthResponse:
    """Framework-agnostic HTTP response representation.
    
    This class provides a common interface for HTTP responses that AAuth
    operations can work with, independent of the underlying framework.
    
    Attributes:
        status_code: HTTP status code (200, 401, etc.)
        headers: Response headers dictionary
        body: Response body bytes (None if no body)
    """
    
    def __init__(
        self,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None
    ):
        """Initialize AAuthResponse.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body bytes
        """
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
    
    @classmethod
    def from_dict(cls, data: Dict) -> "AAuthResponse":
        """Create AAuthResponse from dictionary.
        
        Args:
            data: Dictionary with keys: status_code, headers (optional),
                  body (optional)
        
        Returns:
            AAuthResponse instance
        """
        return cls(
            status_code=data["status_code"],
            headers=data.get("headers"),
            body=data.get("body")
        )
    
    @classmethod
    def from_fastapi_response(cls, response) -> "AAuthResponse":
        """Create AAuthResponse from FastAPI Response object.
        
        Args:
            response: FastAPI Response object
        
        Returns:
            AAuthResponse instance
        
        Note:
            This is a convenience method. The library remains framework-agnostic.
        """
        try:
            from fastapi.responses import Response as FastAPIResponse
            
            if not isinstance(response, FastAPIResponse):
                raise ValueError("Expected FastAPI Response object")
            
            # Extract body if available
            body = None
            if hasattr(response, "body"):
                body = response.body
            
            return cls(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body
            )
        except ImportError:
            raise ValueError("FastAPI not installed. Use from_dict() or construct directly.")
    
    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get header value (case-insensitive).
        
        Args:
            name: Header name (case-insensitive)
            default: Default value if header not found
        
        Returns:
            Header value or default
        """
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return default
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"AAuthResponse(status_code={self.status_code}, "
            f"headers={len(self.headers)} headers)"
        )

