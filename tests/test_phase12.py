"""Tests for Phase 12: Person Server metadata."""

from aauth.metadata.mission_manager import generate_ps_metadata


def test_generate_ps_metadata():
    m = generate_ps_metadata(
        person_server="https://ps.example",
        auth_token_endpoint="https://ps.example/token",
        person_token_endpoint="https://ps.example/person",
        mission_endpoint="https://ps.example/mission",
        jwks_uri="https://ps.example/jwks.json",
    )
    assert m["issuer"] == "https://ps.example"
    assert m["auth_token_endpoint"] == "https://ps.example/token"
    assert m["mission_endpoint"] == "https://ps.example/mission"
    assert m["jwks_uri"] == "https://ps.example/jwks.json"
