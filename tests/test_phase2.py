"""Tests for Phase 2: Agent Identity via JWKS."""

import pytest
import asyncio
import httpx
from participants.agent import Agent
from participants.resource import Resource
from aauth.metadata.agent import generate_agent_metadata
from aauth.metadata.auth_server import fetch_metadata
from aauth.signing.signer import sign_request
from aauth.signing.verifier import verify_signature
from aauth.headers.signature_key import build_signature_key_header
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, generate_jwks, jwk_to_public_key
from aauth.errors import SignatureError


class TestMetadata:
    """Tests for metadata generation and fetching."""
    
    def test_generate_agent_metadata(self):
        """Test metadata generation."""
        agent_id = "https://agent.example.com"
        jwks_uri = "https://agent.example.com/jwks.json"
        
        metadata = generate_agent_metadata(agent_id, jwks_uri)
        
        assert metadata["agent"] == agent_id
        assert metadata["jwks_uri"] == jwks_uri
        assert len(metadata) == 2  # Only required fields
    
    @pytest.mark.asyncio
    async def test_fetch_metadata(self):
        """Test metadata fetching from agent."""
        # Start agent server
        agent = Agent("https://agent.example.com", port=8001)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        try:
            # Fetch metadata
            metadata = fetch_metadata("http://127.0.0.1:8001/.well-known/aauth-agent")
            
            assert metadata["agent"] == "https://agent.example.com"
            assert metadata["jwks_uri"] == "https://agent.example.com/jwks.json"
        finally:
            # Server will be killed when thread dies
            pass
    
    def test_fetch_metadata_https_required(self):
        """Test that metadata fetching requires HTTPS."""
        with pytest.raises(ValueError, match="HTTPS"):
            fetch_metadata("http://agent.example.com/.well-known/aauth-agent")


class TestJWKS:
    """Tests for JWKS handling."""
    
    def test_jwks_includes_kid(self):
        """Test that JWKS includes kid."""
        private_key, public_key = generate_ed25519_keypair()
        kid = "key-1"
        
        jwk = public_key_to_jwk(public_key, kid=kid)
        jwks = generate_jwks([jwk])
        
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kid"] == kid
    
    @pytest.mark.asyncio
    async def test_fetch_jwks_from_agent(self):
        """Test fetching JWKS from agent."""
        # Start agent server
        agent = Agent("https://agent.example.com", port=8001)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        try:
            # Fetch JWKS
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:8001/jwks.json")
                assert response.status_code == 200
                
                jwks = response.json()
                assert "keys" in jwks
                assert len(jwks["keys"]) == 1
                assert jwks["keys"][0]["kid"] == agent.kid
        finally:
            pass


class TestSignatureGeneration:
    """Tests for sig=jwks signature generation."""
    
    def test_build_signature_key_header_jwks(self):
        """Test Signature-Key header generation for sig=jwks."""
        private_key, _ = generate_ed25519_keypair()
        agent_id = "https://agent.example.com"
        kid = "key-1"
        
        header = build_signature_key_header(
            "jwks",
            private_key,
            label="sig1",
            id=agent_id,
            kid=kid
        )
        
        assert header.startswith("sig1=(")
        assert 'scheme=jwks' in header
        assert f'id="{agent_id}"' in header
        assert f'kid="{kid}"' in header
    
    def test_sign_request_jwks(self):
        """Test signing request with sig=jwks."""
        private_key, _ = generate_ed25519_keypair()
        agent_id = "https://agent.example.com"
        kid = "key-1"
        
        headers = sign_request(
            method="GET",
            target_uri="https://resource.example.com/data-jwks",
            headers={},
            body=b"",
            private_key=private_key,
            sig_scheme="jwks",
            id=agent_id,
            kid=kid
        )
        
        assert "Signature-Input" in headers
        assert "Signature" in headers
        assert "Signature-Key" in headers
        
        # Verify Signature-Key format
        sig_key = headers["Signature-Key"]
        assert 'scheme=jwks' in sig_key
        assert f'id="{agent_id}"' in sig_key
        assert f'kid="{kid}"' in sig_key
    
    def test_sign_request_with_query_includes_leading_question_mark(self):
        """Test that @query component includes leading ? per RFC 9421 Section 2.2.7."""
        from aauth.signing.signature_base import build_signature_base, build_signature_params
        
        private_key, _ = generate_ed25519_keypair()
        signature_key_header = build_signature_key_header(
            "hwk",
            private_key,
            label="sig1"
        )
        
        # Build signature base with query
        covered_components = ["@method", "@authority", "@path", "@query", "signature-key"]
        signature_params = build_signature_params(covered_components, created=1234567890)
        
        signature_base = build_signature_base(
            method="GET",
            authority="example.com",
            path="/data",
            query="param=value",
            headers={},
            body=None,
            signature_key_header=signature_key_header,
            covered_components=covered_components,
            signature_params=signature_params
        )
        
        # Verify @query includes leading ?
        assert '"@query": ?param=value' in signature_base
    
    def test_sign_request_with_nonce(self):
        """Test signing request with Nonce header (per SPEC.md Section 10.5)."""
        private_key, _ = generate_ed25519_keypair()
        
        # Sign request with Nonce header
        headers = sign_request(
            method="POST",
            target_uri="https://resource.example.com/data",
            headers={"Nonce": "Y3VyaW91c2x5Y3VyaW91cw", "Content-Type": "application/json"},
            body=b'{"action": "test"}',
            private_key=private_key,
            sig_scheme="hwk"
        )
        
        # Verify nonce is in Signature-Input
        assert "nonce" in headers["Signature-Input"]
        assert "Nonce" in headers  # Header should be preserved
    
    def test_body_components_opt_in(self):
        """Test that body components are opt-in, not automatic."""
        from aauth.signing.signature_base import _determine_covered_components
        
        # Without body, should not include body components
        components = _determine_covered_components(None, None)
        assert "content-type" not in components
        assert "content-digest" not in components
        
        # With body but no additional_components, should not include body components
        components = _determine_covered_components(None, b"test")
        assert "content-type" not in components
        assert "content-digest" not in components
        
        # With body and explicit additional_components, should include them
        components = _determine_covered_components(
            None, 
            b"test",
            additional_components=["content-type", "content-digest"]
        )
        assert "content-type" in components
        assert "content-digest" in components
    
    def test_signature_params_required(self):
        """Test that @signature-params is required in signature base."""
        from aauth.signing.signature_base import build_signature_base
        
        private_key, _ = generate_ed25519_keypair()
        signature_key_header = build_signature_key_header(
            "hwk",
            private_key,
            label="sig1"
        )
        
        # Should raise ValueError if signature_params is missing
        with pytest.raises(ValueError, match="signature_params is required"):
            build_signature_base(
                method="GET",
                authority="example.com",
                path="/data",
                query=None,
                headers={},
                body=None,
                signature_key_header=signature_key_header,
                covered_components=["@method", "@authority", "@path", "signature-key"],
                signature_params=None
            )


class TestSignatureVerification:
    """Tests for sig=jwks signature verification."""
    
    def test_verify_signature_jwks_with_fetcher(self):
        """Test verifying sig=jwks signature with jwks_fetcher."""
        private_key, public_key = generate_ed25519_keypair()
        agent_id = "https://agent.example.com"
        kid = "key-1"
        
        # Sign request
        headers = sign_request(
            method="GET",
            target_uri="https://resource.example.com/data-jwks",
            headers={},
            body=b"",
            private_key=private_key,
            sig_scheme="jwks",
            id=agent_id,
            kid=kid
        )
        
        # Create jwks_fetcher that returns JWKS document
        def jwks_fetcher(agent_id_param, kid_param=None):
            if agent_id_param == agent_id:
                jwk = public_key_to_jwk(public_key, kid=kid)
                return {"keys": [jwk]}
            return None
        
        # Verify signature
        is_valid = verify_signature(
            method="GET",
            target_uri="https://resource.example.com/data-jwks",
            headers={},
            body=b"",
            signature_input_header=headers["Signature-Input"],
            signature_header=headers["Signature"],
            signature_key_header=headers["Signature-Key"],
            jwks_fetcher=jwks_fetcher
        )
        
        assert is_valid
    
    def test_verify_signature_jwks_missing_fetcher(self):
        """Test that sig=jwks requires jwks_fetcher."""
        private_key, _ = generate_ed25519_keypair()
        agent_id = "https://agent.example.com"
        kid = "key-1"
        
        # Sign request
        headers = sign_request(
            method="GET",
            target_uri="https://resource.example.com/data-jwks",
            headers={},
            body=b"",
            private_key=private_key,
            sig_scheme="jwks",
            id=agent_id,
            kid=kid
        )
        
        # Try to verify without jwks_fetcher
        with pytest.raises((ValueError, SignatureError), match="jwks_fetcher"):
            verify_signature(
                method="GET",
                target_uri="https://resource.example.com/data-jwks",
                headers={},
                body=b"",
                signature_input_header=headers["Signature-Input"],
                signature_header=headers["Signature"],
                signature_key_header=headers["Signature-Key"]
            )


class TestSchemeValidation:
    """Tests for scheme validation."""
    
    @pytest.mark.asyncio
    async def test_resource_rejects_wrong_scheme(self):
        """Test that resource rejects requests with wrong scheme."""
        # Start resource server
        resource = Resource("https://resource.example.com", port=8002)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        try:
            # Create agent
            agent = Agent("https://agent.example.com", port=8001)
            
            # Sign request with sig=hwk
            headers = agent.sign_request(
                "GET",
                "http://127.0.0.1:8002/data-jwks",
                sig_scheme="hwk"
            )
            
            # Try to access /data-jwks with sig=hwk (should fail)
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "http://127.0.0.1:8002/data-jwks",
                    headers=headers
                )
                
                assert response.status_code == 401
                assert "Invalid signature scheme" in response.text
        finally:
            pass


class TestIntegration:
    """Integration tests for Phase 2."""
    
    @pytest.mark.asyncio
    async def test_hwk_endpoint_with_hwk_scheme(self):
        """Test /data-hwk endpoint with sig=hwk."""
        # Start resource server
        resource = Resource("https://resource.example.com", port=8002)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        try:
            # Create agent
            agent = Agent("https://agent.example.com", port=8001)
            
            # Request /data-hwk with sig=hwk
            response = await agent.request_resource(
                "http://127.0.0.1:8002/data-hwk",
                sig_scheme="hwk"
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["scheme"] == "hwk"
        finally:
            pass
    
    @pytest.mark.asyncio
    async def test_jwks_endpoint_with_jwks_scheme(self):
        """Test /data-jwks endpoint with sig=jwks."""
        # Start resource server
        resource = Resource("https://resource.example.com", port=8002)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        # Start agent server with local URL
        agent = Agent("http://127.0.0.1:8001", port=8001)
        
        # Start agent server in background
        agent_thread = threading.Thread(
            target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="error"),
            daemon=True
        )
        agent_thread.start()
        
        # Wait for servers to start
        await asyncio.sleep(1)
        
        try:
            # Request /data-jwks with sig=jwks
            response = await agent.request_resource(
                "http://127.0.0.1:8002/data-jwks",
                sig_scheme="jwks"
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["scheme"] == "jwks"
            assert "agent_id" in data
        finally:
            pass
    
    @pytest.mark.asyncio
    async def test_both_endpoints_work_independently(self):
        """Test that both endpoints work independently."""
        # Start resource server
        resource = Resource("https://resource.example.com", port=8002)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        # Start agent server with local URL
        agent = Agent("http://127.0.0.1:8001", port=8001)
        
        # Start agent server in background
        agent_thread = threading.Thread(
            target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="error"),
            daemon=True
        )
        agent_thread.start()
        
        # Wait for servers to start
        await asyncio.sleep(1)
        
        try:
            # Test /data-hwk with sig=hwk
            response_hwk = await agent.request_resource(
                "http://127.0.0.1:8002/data-hwk",
                sig_scheme="hwk"
            )
            assert response_hwk.status_code == 200
            assert response_hwk.json()["scheme"] == "hwk"
            
            # Test /data-jwks with sig=jwks
            response_jwks = await agent.request_resource(
                "http://127.0.0.1:8002/data-jwks",
                sig_scheme="jwks"
            )
            assert response_jwks.status_code == 200
            assert response_jwks.json()["scheme"] == "jwks"
        finally:
            pass


class TestBackwardCompatibility:
    """Tests for backward compatibility with Phase 1."""
    
    @pytest.mark.asyncio
    async def test_original_data_endpoint_still_works(self):
        """Test that /data endpoint still works (defaults to sig=hwk)."""
        # Start resource server
        resource = Resource("https://resource.example.com", port=8002)
        
        # Start server in background
        import uvicorn
        import threading
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="error"),
            daemon=True
        )
        server_thread.start()
        
        # Wait for server to start
        await asyncio.sleep(1)
        
        try:
            # Create agent
            agent = Agent("https://agent.example.com", port=8001)
            
            # Request /data with default sig=hwk
            response = await agent.request_resource(
                "http://127.0.0.1:8002/data"
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["scheme"] == "hwk"
        finally:
            pass

