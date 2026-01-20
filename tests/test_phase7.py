"""Tests for Phase 7: Token Exchange."""

import pytest
import asyncio
import threading
import time
import json
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from aauth.tokens.auth_token import parse_token_claims, create_auth_token
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk


def run_server(server):
    """Run a server in a separate thread."""
    try:
        server.run()
    except:
        pass


@pytest.fixture
def agent1_id():
    return "http://127.0.0.1:8001"


@pytest.fixture
def resource1_id():
    return "http://127.0.0.1:8002"


@pytest.fixture
def resource2_id():
    return "http://127.0.0.1:8004"


@pytest.fixture
def auth1_id():
    return "http://127.0.0.1:8003"


@pytest.fixture
def auth2_id():
    return "http://127.0.0.1:8005"


@pytest.fixture
def agent1(agent1_id):
    return Agent(agent1_id, port=8001, use_user_simulator=True)


@pytest.fixture
def resource1(resource1_id, auth1_id):
    return Resource(resource1_id, port=8002, auth_server=auth1_id)


@pytest.fixture
def resource2(resource2_id, auth2_id):
    return Resource(resource2_id, port=8004, auth_server=auth2_id)


@pytest.fixture
def auth_server1(auth1_id):
    return AuthServer(auth1_id, port=8003, require_user_consent=False)


@pytest.fixture
def auth_server2(auth2_id, auth1_id):
    # Auth Server 2 trusts Auth Server 1
    return AuthServer(auth2_id, port=8005, require_user_consent=False, trusted_auth_servers=[auth1_id])


class TestActClaimCreation:
    """Test act claim creation in auth tokens."""
    
    def test_create_auth_token_with_act_claim(self):
        """Test that auth token can be created with act claim."""
        private_key, public_key = generate_ed25519_keypair()
        cnf_jwk = public_key_to_jwk(public_key, kid="test-key")
        
        act_claim = {
            "agent": "https://original-agent.example",
            "agent_delegate": "delegate-1",
            "sub": "user-123"
        }
        
        token = create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://intermediate-agent.example",
            cnf_jwk=cnf_jwk,
            scope="read write",
            private_key=private_key,
            kid="auth-key-1",
            sub="user-123",
            act=act_claim
        )
        
        # Parse token
        claims = parse_token_claims(token)
        payload = claims["payload"]
        
        # Verify act claim is present
        assert "act" in payload, "act claim should be present"
        assert payload["act"]["agent"] == "https://original-agent.example"
        assert payload["act"]["agent_delegate"] == "delegate-1"
        assert payload["act"]["sub"] == "user-123"
    
    def test_create_auth_token_with_nested_act(self):
        """Test that auth token can be created with nested act claim."""
        private_key, public_key = generate_ed25519_keypair()
        cnf_jwk = public_key_to_jwk(public_key, kid="test-key")
        
        # Nested act for multi-hop chain
        nested_act = {
            "agent": "https://first-agent.example",
            "sub": "user-original"
        }
        
        act_claim = {
            "agent": "https://second-agent.example",
            "sub": "user-123",
            "act": nested_act
        }
        
        token = create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://third-agent.example",
            cnf_jwk=cnf_jwk,
            scope="read",
            private_key=private_key,
            kid="auth-key-1",
            act=act_claim
        )
        
        # Parse token
        claims = parse_token_claims(token)
        payload = claims["payload"]
        
        # Verify nested act claim
        assert "act" in payload
        assert "act" in payload["act"]
        assert payload["act"]["act"]["agent"] == "https://first-agent.example"
    
    def test_create_auth_token_without_act(self):
        """Test that auth token without act claim works normally."""
        private_key, public_key = generate_ed25519_keypair()
        cnf_jwk = public_key_to_jwk(public_key, kid="test-key")
        
        token = create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://agent.example",
            cnf_jwk=cnf_jwk,
            scope="read",
            private_key=private_key,
            kid="auth-key-1"
        )
        
        # Parse token
        claims = parse_token_claims(token)
        payload = claims["payload"]
        
        # Verify act claim is NOT present
        assert "act" not in payload, "act claim should not be present when not specified"


class TestFederationTrust:
    """Test federation trust configuration."""
    
    def test_auth_server_with_trusted_servers(self, auth2_id, auth1_id):
        """Test that auth server can be created with trusted servers list."""
        auth_server = AuthServer(
            auth2_id,
            port=8005,
            trusted_auth_servers=[auth1_id, "https://other-auth.example"]
        )
        
        assert auth_server.trusted_auth_servers == [auth1_id, "https://other-auth.example"]
    
    def test_auth_server_without_trusted_servers(self, auth1_id):
        """Test that auth server defaults to empty trusted servers list."""
        auth_server = AuthServer(auth1_id, port=8003)
        
        assert auth_server.trusted_auth_servers == []


@pytest.mark.asyncio
async def test_token_exchange_flow(
    agent1, resource1, resource2, auth_server1, auth_server2,
    agent1_id, resource1_id, resource2_id, auth1_id, auth2_id
):
    """Test the complete token exchange flow."""
    from flows.autonomous import run_autonomous_flow
    
    # Start all servers
    threads = [
        threading.Thread(target=run_server, args=(agent1,), daemon=True),
        threading.Thread(target=run_server, args=(resource1,), daemon=True),
        threading.Thread(target=run_server, args=(resource2,), daemon=True),
        threading.Thread(target=run_server, args=(auth_server1,), daemon=True),
        threading.Thread(target=run_server, args=(auth_server2,), daemon=True),
    ]
    
    for t in threads:
        t.start()
    
    # Wait for servers to start
    await asyncio.sleep(2)
    
    try:
        # Step 1: Agent 1 gets auth token for Resource 1
        resource1_url = f"{resource1_id}/data-auth"
        await run_autonomous_flow(
            agent=agent1,
            resource=resource1,
            auth_server=auth_server1,
            resource_url=resource1_url,
            method="GET"
        )
        
        auth_token_for_r1 = agent1.auth_token
        assert auth_token_for_r1 is not None, "Should obtain auth token for Resource 1"
        
        # Verify token claims
        claims1 = parse_token_claims(auth_token_for_r1)
        assert claims1["payload"]["aud"] == resource1_id
        assert claims1["payload"]["agent"] == agent1_id
        
        # Step 2: Resource 1 calls Resource 2 via token exchange
        resource2_url = f"{resource2_id}/data-auth"
        
        response = await resource1.call_downstream_resource(
            downstream_url=resource2_url,
            method="GET",
            upstream_auth_token=auth_token_for_r1
        )
        
        assert response.status_code == 200, f"Should access Resource 2: {response.text}"
        
    except Exception as e:
        pytest.fail(f"Token exchange flow failed: {e}")


@pytest.mark.asyncio
async def test_token_exchange_returns_act_claim(
    agent1, resource1, resource2, auth_server1, auth_server2,
    agent1_id, resource1_id, resource2_id, auth1_id, auth2_id
):
    """Test that token exchange returns token with act claim."""
    from flows.autonomous import run_autonomous_flow
    from aauth.signing.signer import sign_request
    
    # Start all servers
    threads = [
        threading.Thread(target=run_server, args=(agent1,), daemon=True),
        threading.Thread(target=run_server, args=(resource1,), daemon=True),
        threading.Thread(target=run_server, args=(resource2,), daemon=True),
        threading.Thread(target=run_server, args=(auth_server1,), daemon=True),
        threading.Thread(target=run_server, args=(auth_server2,), daemon=True),
    ]
    
    for t in threads:
        t.start()
    
    await asyncio.sleep(2)
    
    try:
        # Get auth token for Resource 1
        resource1_url = f"{resource1_id}/data-auth"
        await run_autonomous_flow(
            agent=agent1,
            resource=resource1,
            auth_server=auth_server1,
            resource_url=resource1_url,
            method="GET"
        )
        
        auth_token_for_r1 = agent1.auth_token
        assert auth_token_for_r1 is not None
        
        # Get resource token from Resource 2 by sending a signed request
        import httpx
        import re
        
        # Sign the request with Resource 1's identity
        resource2_data_url = f"{resource2_id}/data-auth"
        sig_headers = sign_request(
            method="GET",
            target_uri=resource2_data_url,
            headers={},
            body=b"",
            private_key=resource1.private_key,
            sig_scheme="jwks",
            id=resource1.resource_id,
            kid=resource1.kid,
            **{"well-known": "aauth-resource"}
        )
        
        async with httpx.AsyncClient() as client:
            initial_response = await client.get(resource2_data_url, headers=sig_headers)
        
        agent_auth_header = initial_response.headers.get("Agent-Auth", "")
        resource_token_match = re.search(r'resource_token="([^"]+)"', agent_auth_header)
        
        assert resource_token_match, f"Should have resource_token in challenge, got: {agent_auth_header}"
        resource_token = resource_token_match.group(1)
        
        # Perform token exchange
        exchanged_token = await resource1._exchange_token(
            auth_server=auth2_id,
            resource_token=resource_token,
            upstream_auth_token=auth_token_for_r1
        )
        
        assert exchanged_token is not None, "Should obtain exchanged token"
        
        # Parse and verify act claim
        claims = parse_token_claims(exchanged_token)
        payload = claims["payload"]
        
        # Should have act claim showing delegation chain
        assert "act" in payload, "Exchanged token should have act claim"
        assert payload["act"]["agent"] == agent1_id, "act.agent should be original agent"
        
        # Other claims
        assert payload["iss"] == auth2_id, "Issuer should be Auth Server 2"
        assert payload["aud"] == resource2_id, "Audience should be Resource 2"
        assert payload["agent"] == resource1_id, "Agent should be Resource 1 (as agent)"
        
    except Exception as e:
        pytest.fail(f"Act claim verification failed: {e}")


@pytest.mark.asyncio
async def test_untrusted_auth_server_rejected(
    agent1, resource1, resource2, auth_server1,
    agent1_id, resource1_id, resource2_id, auth1_id, auth2_id
):
    """Test that token exchange fails when upstream auth server is not trusted."""
    from flows.autonomous import run_autonomous_flow
    from aauth.signing.signer import sign_request
    
    # Create Auth Server 2 WITHOUT trusting Auth Server 1
    auth_server2_untrusted = AuthServer(
        auth2_id,
        port=8005,
        require_user_consent=False,
        trusted_auth_servers=[]  # Empty - doesn't trust anyone
    )
    
    # Start servers
    threads = [
        threading.Thread(target=run_server, args=(agent1,), daemon=True),
        threading.Thread(target=run_server, args=(resource1,), daemon=True),
        threading.Thread(target=run_server, args=(resource2,), daemon=True),
        threading.Thread(target=run_server, args=(auth_server1,), daemon=True),
        threading.Thread(target=run_server, args=(auth_server2_untrusted,), daemon=True),
    ]
    
    for t in threads:
        t.start()
    
    await asyncio.sleep(2)
    
    try:
        # Get auth token for Resource 1
        resource1_url = f"{resource1_id}/data-auth"
        await run_autonomous_flow(
            agent=agent1,
            resource=resource1,
            auth_server=auth_server1,
            resource_url=resource1_url,
            method="GET"
        )
        
        auth_token_for_r1 = agent1.auth_token
        assert auth_token_for_r1 is not None
        
        # Get resource token from Resource 2 by sending a signed request
        import httpx
        import re
        
        resource2_data_url = f"{resource2_id}/data-auth"
        sig_headers = sign_request(
            method="GET",
            target_uri=resource2_data_url,
            headers={},
            body=b"",
            private_key=resource1.private_key,
            sig_scheme="jwks",
            id=resource1.resource_id,
            kid=resource1.kid,
            **{"well-known": "aauth-resource"}
        )
        
        async with httpx.AsyncClient() as client:
            initial_response = await client.get(resource2_data_url, headers=sig_headers)
        
        agent_auth_header = initial_response.headers.get("Agent-Auth", "")
        resource_token_match = re.search(r'resource_token="([^"]+)"', agent_auth_header)
        
        assert resource_token_match, f"Should have resource_token in challenge"
        resource_token = resource_token_match.group(1)
        
        # Token exchange should fail
        exchanged_token = await resource1._exchange_token(
            auth_server=auth2_id,
            resource_token=resource_token,
            upstream_auth_token=auth_token_for_r1
        )
        
        # Should return None since exchange should fail
        assert exchanged_token is None, "Token exchange should fail when auth server is not trusted"
        
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

