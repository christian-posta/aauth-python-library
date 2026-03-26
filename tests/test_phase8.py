"""Tests for Phase 8: Clarification Chat."""

import json

from starlette.testclient import TestClient

from participants.agent import Agent
from participants.auth_server import AuthServer


def test_agent_metadata_declares_clarification_support_by_default():
    """Agent metadata includes clarification_supported=true by default."""
    agent = Agent("http://127.0.0.1:8001", port=8001)
    client = TestClient(agent.app)
    r = client.get("/.well-known/aauth-agent.json")
    assert r.status_code == 200
    assert r.json().get("clarification_supported") is True


def test_agent_metadata_can_disable_clarification_support():
    """Agent metadata can explicitly disable clarification support."""
    agent = Agent("http://127.0.0.1:8001", port=8001, clarification_supported=False)
    client = TestClient(agent.app)
    r = client.get("/.well-known/aauth-agent.json")
    assert r.status_code == 200
    assert r.json().get("clarification_supported") is False


def test_pending_get_includes_clarification_when_supported():
    """Pending polling response includes clarification for supporting agents."""
    auth_server = AuthServer(
        "http://127.0.0.1:8003",
        port=8003,
        require_user_consent=True,
        clarification_questions=["Why do you need this access?"],
    )

    resp = auth_server._create_pending_request(
        agent_id="http://127.0.0.1:8001",
        resource_id="http://127.0.0.1:8002",
        scope="data.read",
        agent_jwk={"kty": "OKP", "crv": "Ed25519", "x": "11"},
        clarification_supported=True,
    )
    assert resp.status_code == 202

    pending_id = next(iter(auth_server.pending_requests))
    client = TestClient(auth_server.app)
    poll = client.get(f"/pending/{pending_id}")
    assert poll.status_code == 202
    body = poll.json()
    assert body.get("status") == "pending"
    assert body.get("clarification") == "Why do you need this access?"


def test_pending_get_omits_clarification_when_unsupported():
    """Pending polling response omits clarification for unsupported agents."""
    auth_server = AuthServer(
        "http://127.0.0.1:8003",
        port=8003,
        require_user_consent=True,
        clarification_questions=["Why do you need this access?"],
    )

    resp = auth_server._create_pending_request(
        agent_id="http://127.0.0.1:8001",
        resource_id="http://127.0.0.1:8002",
        scope="data.read",
        agent_jwk={"kty": "OKP", "crv": "Ed25519", "x": "11"},
        clarification_supported=False,
    )
    assert resp.status_code == 202

    pending_id = next(iter(auth_server.pending_requests))
    client = TestClient(auth_server.app)
    poll = client.get(f"/pending/{pending_id}")
    assert poll.status_code == 202
    body = poll.json()
    assert body.get("status") == "pending"
    assert "clarification" not in body


def test_pending_post_records_clarification_response():
    """POST /pending stores clarification responses in pending history."""
    auth_server = AuthServer(
        "http://127.0.0.1:8003",
        port=8003,
        require_user_consent=True,
        clarification_questions=["Why do you need this access?"],
    )

    resp = auth_server._create_pending_request(
        agent_id="http://127.0.0.1:8001",
        resource_id="http://127.0.0.1:8002",
        scope="data.read",
        agent_jwk={"kty": "OKP", "crv": "Ed25519", "x": "11"},
        clarification_supported=True,
    )
    assert resp.status_code == 202
    pending_id = next(iter(auth_server.pending_requests))

    client = TestClient(auth_server.app)
    post_resp = client.post(
        f"/pending/{pending_id}",
        content=json.dumps({"clarification_response": "Because I need it for scheduling"}),
        headers={"Content-Type": "application/json"},
    )
    assert post_resp.status_code == 202

    history = auth_server.pending_requests[pending_id].get("clarification_history", [])
    assert len(history) == 1
    assert history[0]["response"] == "Because I need it for scheduling"
