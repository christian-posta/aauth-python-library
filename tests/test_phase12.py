"""Tests for Phase 12: Mission Manager metadata."""

from aauth.metadata.mission_manager import generate_mm_metadata


def test_generate_mm_metadata():
    m = generate_mm_metadata(
        manager="https://mm.example",
        token_endpoint="https://mm.example/token",
        mission_endpoint="https://mm.example/mission",
        jwks_uri="https://mm.example/jwks.json",
    )
    assert m["manager"] == "https://mm.example"
    assert m["token_endpoint"] == "https://mm.example/token"
    assert m["mission_endpoint"] == "https://mm.example/mission"
    assert m["jwks_uri"] == "https://mm.example/jwks.json"
