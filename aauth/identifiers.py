"""Server and agent identifier validation for AAuth.

Per spec: server identifiers use HTTPS URLs; agent identifiers use the ``aauth:``
URI scheme of the form ``aauth:local@domain``.
"""

import re
from urllib.parse import urlparse

# aauth: URI scheme — local part character set per spec
_AAUTH_LOCAL_RE = re.compile(r'^[a-z0-9\-_+.]+$')


def validate_agent_identifier(identifier: str) -> str:
    """Validate an agent identifier per AAuth spec (aauth:local@domain format).

    Agent identifiers MUST be of the form ``aauth:local@domain`` where:
    - The ``local`` part consists of lowercase ASCII letters (a-z), digits (0-9),
      hyphen (-), underscore (_), plus (+), and period (.).
    - The ``local`` part MUST NOT be empty and MUST NOT exceed 255 characters.
    - The ``domain`` part MUST be a valid domain name (no scheme, no port).

    Args:
        identifier: Agent identifier string

    Returns:
        The validated identifier (unchanged if valid)

    Raises:
        ValueError: If the identifier is invalid
    """
    if not identifier:
        raise ValueError("Agent identifier must not be empty")

    if not identifier.startswith("aauth:"):
        raise ValueError(f"Agent identifier must use aauth: scheme: {identifier!r}")

    rest = identifier[len("aauth:"):]
    if "@" not in rest:
        raise ValueError(f"Agent identifier must contain '@' separating local and domain: {identifier!r}")

    local, _, domain = rest.partition("@")

    if not local:
        raise ValueError(f"Agent identifier local part must not be empty: {identifier!r}")

    if len(local) > 255:
        raise ValueError(f"Agent identifier local part must not exceed 255 characters: {identifier!r}")

    if not _AAUTH_LOCAL_RE.match(local):
        raise ValueError(
            f"Agent identifier local part contains invalid characters "
            f"(only a-z, 0-9, -, _, +, . allowed): {identifier!r}"
        )

    if not domain:
        raise ValueError(f"Agent identifier domain part must not be empty: {identifier!r}")

    if "://" in domain:
        raise ValueError(f"Agent identifier domain must not include a scheme: {identifier!r}")

    return identifier


def parse_agent_identifier(identifier: str):
    """Parse an ``aauth:local@domain`` identifier into (local, domain) tuple.

    Raises ValueError if the identifier is invalid.
    """
    validate_agent_identifier(identifier)
    rest = identifier[len("aauth:"):]
    local, _, domain = rest.partition("@")
    return local, domain


def agent_identifier_from_server_url(server_url: str, local: str = "agent") -> str:
    """Derive an aauth: identifier from an agent server URL.

    Extracts the hostname (and port for localhost) from the URL and combines
    with the given local part.

    Examples:
        ``http://127.0.0.1:8001`` → ``aauth:agent@127.0.0.1``
        ``https://agent.example`` → ``aauth:agent@agent.example``
    """
    parsed = urlparse(server_url)
    host = parsed.hostname or "localhost"
    return f"aauth:{local}@{host}"


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
