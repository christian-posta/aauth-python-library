"""Tests for Phase 10: authorization endpoint and metadata."""

from aauth.headers.aauth_header import build_aauth_mission_header, parse_aauth_mission_header
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


def test_aauth_mission_header_roundtrip():
    h = build_aauth_mission_header("https://ps.example", "abcds256")
    p = parse_aauth_mission_header(h)
    assert p["approver"] == "https://ps.example"
    assert p["s256"] == "abcds256"
