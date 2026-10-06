"""Tests for Phase 10: authorization endpoint and metadata."""

from aauth.headers.aauth_header import (
    build_aauth_mission_header,
    parse_aauth_mission_header,
)
from aauth.metadata.resource import generate_resource_metadata


def test_resource_metadata_includes_authorization_endpoint():
    m = generate_resource_metadata(
        "https://resource.example",
        "https://resource.example/jwks.json",
        authorization_endpoint="https://resource.example/authorize",
        signature_window=120,
    )
    assert m["authorization_endpoint"] == "https://resource.example/authorize"
    assert m["signature_window"] == 120


def test_mission_approval_hash_roundtrip():
    from aauth.missions import build_mission_approval, parse_mission_approval

    response = build_mission_approval(
        {"description": "Plan a trip", "approved_at": 123}
    )
    parsed = parse_mission_approval(response)
    assert parsed["mission_s256"] == response["s256"]
    assert parsed["mission"]["description"] == "Plan a trip"
