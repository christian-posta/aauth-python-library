"""Backward compatibility shim — redirects to aauth_header.py."""

from .aauth_header import (
    parse_agent_auth_header,
    build_agent_auth_challenge,
    parse_aauth_header,
    build_pseudonym_challenge,
    build_identity_challenge,
    build_auth_token_challenge,
    build_interaction_challenge,
    build_approval_challenge,
    REQUIRE_PSEUDONYM,
    REQUIRE_IDENTITY,
    REQUIRE_AUTH_TOKEN,
    REQUIRE_INTERACTION,
    REQUIRE_APPROVAL,
)

__all__ = [
    "parse_agent_auth_header",
    "build_agent_auth_challenge",
    "parse_aauth_header",
    "build_pseudonym_challenge",
    "build_identity_challenge",
    "build_auth_token_challenge",
    "build_interaction_challenge",
    "build_approval_challenge",
    "REQUIRE_PSEUDONYM",
    "REQUIRE_IDENTITY",
    "REQUIRE_AUTH_TOKEN",
    "REQUIRE_INTERACTION",
    "REQUIRE_APPROVAL",
]
