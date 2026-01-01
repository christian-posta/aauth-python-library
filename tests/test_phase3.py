"""Tests for Phase 3: Autonomous Authorization."""

import pytest
import asyncio
import httpx
import time
import json
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from core.tokens import (
    create_resource_token, create_auth_token, verify_token,
    calculate_jwk_thumbprint, parse_token_claims
)
from core.crypto_utils import generate_ed25519_keypair, public_key_to_jwk
from core.metadata import generate_resource_metadata, generate_auth_metadata


class TestTokenGeneration:
    """Tests for token generation."""
    
    def test_create_resource_token(self):
        """Test resource token creation."""
        private_key, public_key = generate_ed25519_keypair()
        jwk = public_key_to_jwk(public_key)
        agent_jkt = calculate_jwk_thumbprint(jwk)
        
        token = create_resource_token(
            iss="https://resource.example",
            aud="https://auth.example",
            agent="https://agent.example",
            agent_jkt=agent_jkt,
            scope="data.read data.write",
            private_key=private_key,
            kid="resource-key-1"
        )
        
        assert token is not None
        assert len(token.split('.')) == 3  # JWT has 3 parts
        
        # Parse token to verify claims
        claims = parse_token_claims(token)
        assert claims["header"]["typ"] == "resource+jwt"
        assert claims["payload"]["iss"] == "https://resource.example"
        assert claims["payload"]["aud"] == "https://auth.example"
        assert claims["payload"]["agent"] == "https://agent.example"
        assert claims["payload"]["agent_jkt"] == agent_jkt
        assert claims["payload"]["scope"] == "data.read data.write"
        assert "exp" in claims["payload"]
    
    def test_create_auth_token(self):
        """Test auth token creation."""
        private_key, public_key = generate_ed25519_keypair()
        agent_jwk = public_key_to_jwk(public_key)
        
        token = create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://agent.example",
            cnf_jwk=agent_jwk,
            scope="data.read",
            private_key=private_key,
            kid="auth-key-1"
        )
        
        assert token is not None
        assert len(token.split('.')) == 3  # JWT has 3 parts
        
        # Parse token to verify claims
        claims = parse_token_claims(token)
        assert claims["header"]["typ"] == "auth+jwt"
        assert claims["payload"]["iss"] == "https://auth.example"
        assert claims["payload"]["aud"] == "https://resource.example"
        assert claims["payload"]["agent"] == "https://agent.example"
        assert "cnf" in claims["payload"]
        assert "jwk" in claims["payload"]["cnf"]
        assert claims["payload"]["scope"] == "data.read"
        assert "exp" in claims["payload"]
    
    def test_create_auth_token_with_sub(self):
        """Test auth token creation with user identifier."""
        private_key, public_key = generate_ed25519_keypair()
        agent_jwk = public_key_to_jwk(public_key)
        
        token = create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://agent.example",
            cnf_jwk=agent_jwk,
            scope="data.read",
            private_key=private_key,
            kid="auth-key-1",
            sub="user-12345"
        )
        
        claims = parse_token_claims(token)
        assert claims["payload"]["sub"] == "user-12345"


class TestJWKThumbprint:
    """Tests for JWK thumbprint calculation."""
    
    def test_calculate_jwk_thumbprint(self):
        """Test JWK thumbprint calculation."""
        private_key, public_key = generate_ed25519_keypair()
        jwk = public_key_to_jwk(public_key)
        
        thumbprint = calculate_jwk_thumbprint(jwk)
        
        assert thumbprint is not None
        assert len(thumbprint) > 0
        # Base64url encoded SHA-256 should be 43 characters (no padding)
        assert len(thumbprint) == 43
    
    def test_jwk_thumbprint_consistency(self):
        """Test that same JWK produces same thumbprint."""
        private_key, public_key = generate_ed25519_keypair()
        jwk = public_key_to_jwk(public_key)
        
        thumbprint1 = calculate_jwk_thumbprint(jwk)
        thumbprint2 = calculate_jwk_thumbprint(jwk)
        
        assert thumbprint1 == thumbprint2


class TestTokenVerification:
    """Tests for token verification."""
    
    def test_verify_resource_token(self):
        """Test resource token verification."""
        # Create resource key pair
        resource_private, resource_public = generate_ed25519_keypair()
        resource_jwk = public_key_to_jwk(resource_public)
        
        # Create agent key pair
        agent_private, agent_public = generate_ed25519_keypair()
        agent_jwk = public_key_to_jwk(agent_public)
        agent_jkt = calculate_jwk_thumbprint(agent_jwk)
        
        # Create resource token
        token = create_resource_token(
            iss="https://resource.example",
            aud="https://auth.example",
            agent="https://agent.example",
            agent_jkt=agent_jkt,
            scope="data.read",
            private_key=resource_private,
            kid="resource-key-1"
        )
        
        # JWKS fetcher for resource
        def resource_jwks_fetcher(resource_id: str):
            return {"keys": [resource_jwk]}
        
        # Verify token
        claims = verify_token(
            token=token,
            jwks_fetcher=resource_jwks_fetcher,
            expected_typ="resource+jwt",
            expected_aud="https://auth.example"
        )
        
        assert claims["iss"] == "https://resource.example"
        assert claims["aud"] == "https://auth.example"
        assert claims["agent"] == "https://agent.example"
        assert claims["agent_jkt"] == agent_jkt
        assert claims["scope"] == "data.read"
    
    def test_verify_auth_token(self):
        """Test auth token verification."""
        # Create auth server key pair
        auth_private, auth_public = generate_ed25519_keypair()
        auth_jwk = public_key_to_jwk(auth_public)
        
        # Create agent key pair
        agent_private, agent_public = generate_ed25519_keypair()
        agent_jwk = public_key_to_jwk(agent_public)
        
        # Create auth token
        token = create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://agent.example",
            cnf_jwk=agent_jwk,
            scope="data.read",
            private_key=auth_private,
            kid="auth-key-1"
        )
        
        # JWKS fetcher for auth server
        def auth_jwks_fetcher(auth_id: str):
            return {"keys": [auth_jwk]}
        
        # Verify token
        claims = verify_token(
            token=token,
            jwks_fetcher=auth_jwks_fetcher,
            expected_typ="auth+jwt",
            expected_aud="https://resource.example"
        )
        
        assert claims["iss"] == "https://auth.example"
        assert claims["aud"] == "https://resource.example"
        assert claims["agent"] == "https://agent.example"
        assert "cnf" in claims
        assert "jwk" in claims["cnf"]
        assert claims["scope"] == "data.read"
    
    def test_verify_expired_token(self):
        """Test that expired tokens are rejected."""
        private_key, public_key = generate_ed25519_keypair()
        jwk = public_key_to_jwk(public_key)
        agent_jkt = calculate_jwk_thumbprint(jwk)
        
        # Create token with expiration in the past
        token = create_resource_token(
            iss="https://resource.example",
            aud="https://auth.example",
            agent="https://agent.example",
            agent_jkt=agent_jkt,
            scope="data.read",
            private_key=private_key,
            kid="resource-key-1",
            exp=int(time.time()) - 100  # Expired 100 seconds ago
        )
        
        def jwks_fetcher(resource_id: str):
            return {"keys": [jwk]}
        
        # Verify token should fail
        with pytest.raises(Exception):  # jwt.ExpiredSignatureError
            verify_token(
                token=token,
                jwks_fetcher=jwks_fetcher,
                expected_typ="resource+jwt"
            )


class TestAuthServer:
    """Tests for auth server."""
    
    @pytest.mark.asyncio
    async def test_auth_server_metadata(self):
        """Test auth server metadata endpoint."""
        auth_server = AuthServer("https://auth.example", port=8003)
        
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(auth_server.app, host="127.0.0.1", port=8003, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        await asyncio.sleep(1)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:8003/.well-known/aauth-issuer")
                assert response.status_code == 200
                
                metadata = response.json()
                assert metadata["issuer"] == "https://auth.example"
                assert "jwks_uri" in metadata
                assert "agent_token_endpoint" in metadata
                assert "agent_auth_endpoint" in metadata
        finally:
            pass
    
    @pytest.mark.asyncio
    async def test_auth_server_jwks(self):
        """Test auth server JWKS endpoint."""
        auth_server = AuthServer("https://auth.example", port=8003)
        
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(auth_server.app, host="127.0.0.1", port=8003, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        await asyncio.sleep(1)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:8003/jwks.json")
                assert response.status_code == 200
                
                jwks = response.json()
                assert "keys" in jwks
                assert len(jwks["keys"]) == 1
        finally:
            pass


class TestEndToEndFlow:
    """End-to-end tests for autonomous authorization flow."""
    
    @pytest.mark.asyncio
    async def test_autonomous_flow(self):
        """Test complete autonomous authorization flow."""
        # Create participants
        agent_id = "http://127.0.0.1:8001"
        resource_id = "http://127.0.0.1:8002"
        auth_id = "http://127.0.0.1:8003"
        
        agent = Agent(agent_id, port=8001)
        resource = Resource(resource_id, port=8002, auth_server=auth_id)
        auth_server = AuthServer(auth_id, port=8003)
        
        # Start servers
        import uvicorn
        import threading
        
        agent_thread = threading.Thread(
            target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="error"),
            daemon=True
        )
        resource_thread = threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="error"),
            daemon=True
        )
        auth_thread = threading.Thread(
            target=lambda: uvicorn.run(auth_server.app, host="127.0.0.1", port=8003, log_level="error"),
            daemon=True
        )
        
        agent_thread.start()
        resource_thread.start()
        auth_thread.start()
        
        # Wait for servers to start
        await asyncio.sleep(2)
        
        try:
            # Agent requests resource (should get resource token challenge)
            response = await agent.request_resource(
                resource_url=f"{resource_id}/data-auth",
                method="GET",
                sig_scheme="jwks"
            )
            
            # Should succeed after automatic challenge handling
            assert response.status_code == 200
            
            # Verify agent has auth token
            assert agent.auth_token is not None
            
            # Verify response data
            data = response.json()
            assert "message" in data or "data" in data
            
        finally:
            pass

