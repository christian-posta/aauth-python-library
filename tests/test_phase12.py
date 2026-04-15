"""Tests for Phase 12: Person Server metadata."""

from aauth.metadata.mission_manager import generate_ps_metadata


def test_generate_ps_metadata():
    m = generate_ps_metadata(
        person_server="https://ps.example",
        token_endpoint="https://ps.example/token",
        mission_endpoint="https://ps.example/mission",
        jwks_uri="https://ps.example/jwks.json",
    )
    assert m["issuer"] == "https://ps.example"
    assert m["token_endpoint"] == "https://ps.example/token"
    assert m["mission_endpoint"] == "https://ps.example/mission"
    assert m["jwks_uri"] == "https://ps.example/jwks.json"
