"""Server identifier and URL validation for AAuth.

Per SPEC Section 5, server identifiers and endpoint URLs have strict requirements.
"""

from urllib.parse import urlparse


def validate_server_identifier(url: str) -> str:
    """Validate a server identifier per AAuth spec Section 5.1.

    Server identifiers (agent, resource, issuer) MUST:
    - Use the https scheme
    - Contain only scheme and host (no port, path, query, or fragment)
    - Not include a trailing slash
    - Be lowercase
    - Use ACE form for internationalized domains

    Args:
        url: Server identifier URL

    Returns:
        The validated URL (unchanged if valid)

    Raises:
        ValueError: If the identifier is invalid
    """
    if not url:
        raise ValueError("Server identifier must not be empty")

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(f"Server identifier must use https scheme: {url}")

    if not parsed.hostname:
        raise ValueError(f"Server identifier must have a hostname: {url}")

    if parsed.port is not None:
        raise ValueError(f"Server identifier must not contain a port: {url}")

    if parsed.path and parsed.path != "":
        # urlparse gives '' for no path, '/' for trailing slash, '/foo' for path
        if parsed.path != "":
            raise ValueError(f"Server identifier must not contain a path: {url}")

    if parsed.query:
        raise ValueError(f"Server identifier must not contain a query string: {url}")

    if parsed.fragment:
        raise ValueError(f"Server identifier must not contain a fragment: {url}")

    if url.endswith("/"):
        raise ValueError(f"Server identifier must not include a trailing slash: {url}")

    if url != url.lower():
        raise ValueError(f"Server identifier must be lowercase: {url}")

    return url


def validate_endpoint_url(url: str) -> str:
    """Validate an endpoint URL per AAuth spec Section 5.2.

    Endpoint URLs (token_endpoint, interaction_endpoint, etc.) MUST:
    - Use the https scheme
    - Not contain a fragment
    - Not contain a query string

    Args:
        url: Endpoint URL

    Returns:
        The validated URL (unchanged if valid)

    Raises:
        ValueError: If the URL is invalid
    """
    if not url:
        raise ValueError("Endpoint URL must not be empty")

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(f"Endpoint URL must use https scheme: {url}")

    if parsed.fragment:
        raise ValueError(f"Endpoint URL must not contain a fragment: {url}")

    if parsed.query:
        raise ValueError(f"Endpoint URL must not contain a query string: {url}")

    return url


def validate_other_url(url: str) -> str:
    """Validate other URLs (jwks_uri, tos_uri, etc.) per AAuth spec Section 5.3.

    These URLs MUST use the https scheme.

    Args:
        url: URL to validate

    Returns:
        The validated URL (unchanged if valid)

    Raises:
        ValueError: If the URL is invalid
    """
    if not url:
        raise ValueError("URL must not be empty")

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(f"URL must use https scheme: {url}")

    return url
