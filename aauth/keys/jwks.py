"""JWKS fetching and caching for AAuth.

Implements JWKS Discovery per SPEC §JWKS Discovery:
- Cache JWKS responses, respect HTTP cache headers
- Re-fetch on unknown kid (key rotation support)
- Rate limit: max once per minute per issuer
- Discard cached entries after 24 hours max
"""

import time
from typing import Dict, Any, Optional, Protocol


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
    """In-memory cache for JWKS documents with TTL and max age enforcement.

    Per SPEC §JWKS Discovery:
    - Cached entries SHOULD be discarded after max 24 hours regardless of cache headers.
    """

    def __init__(self, ttl: int = 3600, max_age: int = 86400):
        """Initialize cache.

        Args:
            ttl: Time-to-live in seconds (default: 1 hour)
            max_age: Maximum age in seconds regardless of TTL (default: 24 hours)
        """
        self._cache: Dict[str, tuple[Dict[str, Any], float]] = {}
        self._ttl = ttl
        self._max_age = max_age

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
        now = time.time()

        # Enforce max age (24h hard limit per spec)
        if now - cached_at > self._max_age:
            del self._cache[url]
            return None

        if now - cached_at > self._ttl:
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

    def invalidate(self, url: str) -> None:
        """Invalidate a specific cache entry (e.g., on unknown kid).

        Args:
            url: JWKS URL to invalidate
        """
        self._cache.pop(url, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


class JWKSFetcher:
    """JWKS fetcher with caching, re-fetch on unknown kid, and rate limiting.

    Per SPEC §JWKS Discovery:
    - Re-fetch on unknown kid to support key rotation
    - MUST NOT fetch more than once per minute per issuer
    - Cache entries expire after max 24 hours
    """

    def __init__(
        self,
        http_client: Optional[HTTPClient] = None,
        cache: Optional[JWKSCache] = None,
        cache_ttl: int = 3600,
        min_fetch_interval: int = 60,
    ):
        """Initialize JWKS fetcher.

        Args:
            http_client: HTTP client implementation (default: DefaultHTTPClient)
            cache: Cache implementation (default: JWKSCache with specified TTL)
            cache_ttl: Cache TTL in seconds (used if cache not provided)
            min_fetch_interval: Minimum seconds between fetches per issuer (default: 60)
        """
        self._http_client = http_client or DefaultHTTPClient()
        self._cache = cache or JWKSCache(ttl=cache_ttl)
        self._min_fetch_interval = min_fetch_interval
        self._last_fetch_times: Dict[str, float] = {}

    def _can_fetch(self, identifier: str) -> bool:
        """Check if we can fetch for this identifier (rate limiting)."""
        last = self._last_fetch_times.get(identifier, 0)
        return (time.time() - last) >= self._min_fetch_interval

    def _record_fetch(self, identifier: str) -> None:
        """Record a fetch timestamp for rate limiting."""
        self._last_fetch_times[identifier] = time.time()

    async def fetch(
        self,
        identifier: str,
        kid: Optional[str] = None,
        metadata_path: str = "aauth-agent.json"
    ) -> Dict[str, Any]:
        """Fetch JWKS for an identifier via metadata discovery.

        Performs two-step discovery per SIG-KEY §3.5:
        1. Fetch {identifier}/.well-known/{metadata_path}
        2. Extract jwks_uri from metadata
        3. Fetch JWKS from jwks_uri

        Args:
            identifier: Agent/resource/auth server identifier (HTTPS URL)
            kid: Optional key ID (for cache key and re-fetch on miss)
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

        # Check cache first
        cached = self._cache.get(jwks_uri)
        if cached:
            # If kid specified, check if the key is in the cached JWKS
            if kid:
                key = self.get_key_by_kid(cached, kid)
                if key:
                    return cached
                # Key not found — try re-fetch if rate limit allows
                if not self._can_fetch(identifier):
                    return cached  # Rate limited, return stale cache
                # Fall through to re-fetch
                self._cache.invalidate(jwks_uri)
            else:
                return cached

        # Rate limit check for fresh fetch
        if not self._can_fetch(identifier):
            raise JWKSError(
                f"Rate limited: cannot fetch JWKS for {identifier} more than once per {self._min_fetch_interval}s",
                jwks_uri=jwks_uri
            )

        # Fetch JWKS
        try:
            jwks = await self._http_client.fetch_json(jwks_uri)

            # Validate JWKS structure
            if not isinstance(jwks, dict) or "keys" not in jwks:
                raise JWKSError(
                    f"Invalid JWKS structure from {jwks_uri}",
                    jwks_uri=jwks_uri
                )

            # Cache it and record fetch time
            self._cache.set(jwks_uri, jwks)
            self._record_fetch(identifier)

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
