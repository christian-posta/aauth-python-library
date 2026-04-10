"""Tests for Phase 11: MM–AS federation helpers."""

from aauth.http.deferred import build_pending_response_body, build_pending_response_headers


def test_claims_pending_body_and_headers():
    body = build_pending_response_body(
        "https://as.example/pending/abc",
        require="claims",
        required_claims=["email", "org"],
    )
    assert body["requirement"] == "claims"
    assert body["required_claims"] == ["email", "org"]

    hdrs = build_pending_response_headers(
        "https://as.example/pending/abc",
        retry_after=2,
        require="claims",
        required_claims=["email"],
    )
    assert "AAuth-Requirement" in hdrs
    assert "claims" in hdrs["AAuth-Requirement"]
