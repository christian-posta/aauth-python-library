"""JWKS fetching and caching for AAuth."""

import time
from typing import Dict, Any, Optional, Callable, Protocol
from ..errors import JWKSError


class HTTPClient(Protocol):
    """Protocol for HTTP client implementations."""
    
    async def fetch_json(self, url: str) -> Dict[str, Any]:
        """Fetch JSON from URL.
        
        Args:
            url: URL to fetch
            
        Returns:
            Parsed JSON dictionary
            
        Raises:
            Exception: If fetch fails
        """
        ...


class DefaultHTTPClient:
    """Default httpx-based HTTP client."""
    
    async def fetch_json(self, url: str) -> Dict[str, Any]:
        """Fetch JSON using httpx."""
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=10.0)
                response.raise_for_status()
                return response.json()
        except ImportError:
            raise JWKSError("httpx not installed. Install it or provide custom HTTP client.")
        except Exception as e:
            raise JWKSError(f"Failed to fetch JWKS from {url}: {e}", jwks_uri=url)


class JWKSCache:
    """Simple in-memory cache for JWKS documents."""
    
    def __init__(self, ttl: int = 3600):
        """Initialize cache.
        
        Args:
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self._cache: Dict[str, tuple[Dict[str, Any], float]] = {}
        self._ttl = ttl
    
    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Get cached JWKS if still valid.
        
        Args:
            url: JWKS URL
            
        Returns:
            Cached JWKS or None if expired/not found
        """
        if url not in self._cache:
            return None
        
        jwks, cached_at = self._cache[url]
        if time.time() - cached_at > self._ttl:
            del self._cache[url]
            return None
        
        return jwks
    
    def set(self, url: str, jwks: Dict[str, Any]) -> None:
        """Cache JWKS.
        
        Args:
            url: JWKS URL
            jwks: JWKS document
        """
        self._cache[url] = (jwks, time.time())
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


class JWKSFetcher:
    """JWKS fetcher with caching support."""
    
    def __init__(
        self,
        http_client: Optional[HTTPClient] = None,
        cache: Optional[JWKSCache] = None,
        cache_ttl: int = 3600
    ):
        """Initialize JWKS fetcher.
        
        Args:
            http_client: HTTP client implementation (default: DefaultHTTPClient)
            cache: Cache implementation (default: JWKSCache with specified TTL)
            cache_ttl: Cache TTL in seconds (used if cache not provided)
        """
        self._http_client = http_client or DefaultHTTPClient()
        self._cache = cache or JWKSCache(ttl=cache_ttl)
    
    async def fetch(
        self,
        identifier: str,
        kid: Optional[str] = None,
        metadata_path: str = "aauth-agent.json"
    ) -> Dict[str, Any]:
        """Fetch JWKS for an identifier via metadata discovery.

        Args:
            identifier: Agent/resource/auth server identifier (HTTPS URL)
            kid: Optional key ID (for cache key)
            metadata_path: Well-known metadata filename (default: aauth-agent.json)

        Returns:
            JWKS document dictionary

        Raises:
            JWKSError: If fetch fails
        """
        # Fetch metadata to discover jwks_uri
        metadata_url = f"{identifier}/.well-known/{metadata_path}"
        try:
            metadata = await self._http_client.fetch_json(metadata_url)
            jwks_uri = metadata.get("jwks_uri")
            if not jwks_uri:
                raise JWKSError(
                    f"No jwks_uri in metadata from {metadata_url}",
                    jwks_uri=metadata_url
                )
        except JWKSError:
            raise
        except Exception as e:
            raise JWKSError(
                f"Failed to fetch metadata from {metadata_url}: {e}",
                jwks_uri=metadata_url
            )
        
        # Check cache
        cache_key = f"{jwks_uri}:{kid}" if kid else jwks_uri
        cached = self._cache.get(cache_key)
        if cached:
            return cached
        
        # Fetch JWKS
        try:
            jwks = await self._http_client.fetch_json(jwks_uri)
            
            # Validate JWKS structure
            if not isinstance(jwks, dict) or "keys" not in jwks:
                raise JWKSError(
                    f"Invalid JWKS structure from {jwks_uri}",
                    jwks_uri=jwks_uri
                )
            
            # Cache it
            self._cache.set(cache_key, jwks)
            
            return jwks
        except JWKSError:
            raise
        except Exception as e:
            raise JWKSError(
                f"Failed to fetch JWKS from {jwks_uri}: {e}",
                jwks_uri=jwks_uri
            )
    
    def get_key_by_kid(self, jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
        """Get key from JWKS by kid.
        
        Args:
            jwks: JWKS document
            kid: Key ID
            
        Returns:
            JWK dictionary or None if not found
        """
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid:
                return key
        return None

