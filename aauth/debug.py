"""Debug utilities for AAuth."""

import os
import sys
from typing import Any
from urllib.parse import urlparse

AAUTH_DEBUG_DEFAULT = "0"
AAUTH_DEBUG_HTTP_DEFAULT = "1"
AAUTH_DEBUG_JWT_TOKEN_DEFAULT = "1"


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled.

    Args:
        env_var: Environment variable name to check (default: "AAUTH_DEBUG")

    Returns:
        True if debug is enabled, False otherwise.
    """
    value = os.environ.get(env_var, AAUTH_DEBUG_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_http_debug_enabled() -> bool:
    """Check if HTTP debug is enabled.

    Returns:
        True if HTTP debug is enabled, False otherwise.
    """
    value = os.environ.get("AAUTH_DEBUG_HTTP", AAUTH_DEBUG_HTTP_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_jwt_token_debug_enabled() -> bool:
    """Check if JWT token debug (decoding/printing) is enabled.

    Returns:
        True if JWT token debug is enabled, False otherwise.
    """
    value = os.environ.get("AAUTH_DEBUG_JWT_TOKEN", AAUTH_DEBUG_JWT_TOKEN_DEFAULT)
    return value.lower() not in ("0", "false", "no", "off", "")


def print_stderr_localhost_port_map(
    agent: Any,
    resource: Any,
    auth_server: Any,
    *,
    file: Any = None,
) -> None:
    """Print a compact 127.0.0.1 port → role legend for multi-service demos.

    Helps map ``iss`` / ``aud`` / agent URLs inside JWT payloads to running services.
    When ``agent.mm_url`` is set, includes the Mission Manager port parsed from that URL.
    """
    out = sys.stderr if file is None else file

    rows: list[tuple[int, str, str]] = []
    ap = getattr(agent, "port", None)
    rp = getattr(resource, "port", None)
    asp = getattr(auth_server, "port", None)
    if isinstance(ap, int):
        rows.append(
            (
                ap,
                "Agent server",
                "iss for agent identity; /.well-known/aauth-agent.json; JWKS",
            )
        )
    if isinstance(rp, int):
        rows.append(
            (
                rp,
                "Resource",
                "iss in resource tokens; protected routes (e.g. /data-auth)",
            )
        )
    if isinstance(asp, int):
        rows.append(
            (
                asp,
                "Authorization server",
                "iss in auth tokens; aud in resource tokens; POST /token",
            )
        )
    mm_url = getattr(agent, "mm_url", None)
    if mm_url:
        pu = urlparse(mm_url)
        mp = pu.port or (443 if pu.scheme == "https" else 80)
        rows.append(
            (
                mp,
                "Mission manager",
                "Agent ``POST /token``; MM → AS federation",
            )
        )

    if not rows:
        return

    rows.sort(key=lambda x: x[0])

    print("\n" + "-" * 80, file=out, flush=True)
    print(
        "127.0.0.1 port map (JWT iss / aud / agent URLs below refer to these):",
        file=out,
        flush=True,
    )
    for port, role, detail in rows:
        print(f"  {port:5d}  {role:<22} — {detail}", file=out, flush=True)
    print("-" * 80 + "\n", file=out, flush=True)
