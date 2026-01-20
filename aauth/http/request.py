"""Framework-agnostic HTTP request representation for AAuth."""

from typing import Dict, Optional
from urllib.parse import urlparse


class AAuthRequest:
    """Framework-agnostic HTTP request representation.
    
    This class provides a common interface for HTTP requests that AAuth
    operations can work with, independent of the underlying framework
    (FastAPI, Flask, Django, etc.).
    
    Attributes:
        method: HTTP method (GET, POST, etc.)
        authority: Canonical authority (host:port) per SPEC 10.3.1
        path: Request path (e.g., "/api/data")
        query: Query string (without leading "?")
        headers: Request headers dictionary (case-insensitive keys)
        body: Request body bytes (None if no body)
    """
    
    def __init__(
        self,
        method: str,
        authority: str,
        path: str,
        query: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None
    ):
        """Initialize AAuthRequest.
        
        Args:
            method: HTTP method
            authority: Canonical authority (host:port)
            path: Request path
            query: Query string (without leading "?")
            headers: Request headers
            body: Request body bytes
        """
        self.method = method.upper()
        self.authority = authority
        self.path = path or "/"
        self.query = query
        self.headers = headers or {}
        self.body = body
    
    @classmethod
    def from_dict(cls, data: Dict) -> "AAuthRequest":
        """Create AAuthRequest from dictionary.
        
        Args:
            data: Dictionary with keys: method, authority, path, query (optional),
                  headers (optional), body (optional)
        
        Returns:
            AAuthRequest instance
        """
        return cls(
            method=data["method"],
            authority=data["authority"],
            path=data.get("path", "/"),
            query=data.get("query"),
            headers=data.get("headers"),
            body=data.get("body")
        )
    
    @classmethod
    def from_fastapi_request(cls, request) -> "AAuthRequest":
        """Create AAuthRequest from FastAPI Request object.
        
        Args:
            request: FastAPI Request object
        
        Returns:
            AAuthRequest instance
        
        Note:
            This is a convenience method. The library remains framework-agnostic.
        """
        try:
            from fastapi import Request as FastAPIRequest
            
            if not isinstance(request, FastAPIRequest):
                raise ValueError("Expected FastAPI Request object")
            
            # Extract authority from URL
            parsed_url = urlparse(str(request.url))
            authority = parsed_url.netloc
            
            # Extract query string (without leading "?")
            query = parsed_url.query if parsed_url.query else None
            
            # Extract headers (FastAPI uses case-insensitive headers)
            headers = dict(request.headers)
            
            # Get body if available
            body = None
            if hasattr(request, "_body"):
                body = request._body
            elif hasattr(request, "body"):
                # For async requests, body() is a coroutine
                # This is a limitation - users should read body separately
                pass
            
            return cls(
                method=request.method,
                authority=authority,
                path=parsed_url.path,
                query=query,
                headers=headers,
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
            f"AAuthRequest(method={self.method!r}, authority={self.authority!r}, "
            f"path={self.path!r}, query={self.query!r})"
        )

