"""Tests for Phase 9: Interaction Chaining."""

from starlette.testclient import TestClient

from participants.resource import Resource


def test_resource_interact_redirects_to_downstream_interaction():
    """Resource 1 interaction endpoint redirects to downstream interaction endpoint."""
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    pending_id = "pending-1"
    resource.chained_pending_requests[pending_id] = {
        "local_interaction_code": "LOCAL123",
        "downstream_code": "DOWN456",
        "downstream_interaction_endpoint": "http://127.0.0.1:8005/interact",
    }
    client = TestClient(resource.app)
    response = client.get("/interact?code=LOCAL123", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "http://127.0.0.1:8005/interact?code=DOWN456"


def test_resource_interact_rejects_unknown_code():
    """Resource 1 interaction endpoint rejects unknown interaction code."""
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    client = TestClient(resource.app)
    response = client.get("/interact?code=UNKNOWN")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_resource_pending_returns_not_found_when_missing():
    """Resource 1 pending endpoint returns 404 for unknown pending ID."""
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    client = TestClient(resource.app)
    response = client.get("/pending/missing")
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"
