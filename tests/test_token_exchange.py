"""Tests for PS token exchange (three-party mode, SPEC §4.1.3)."""

import pytest
import asyncio
import json
import time
from typing import Dict, Any
from urllib.parse import urlparse

from aauth.agent.token_exchange import extract_resource_token, exchange_resource_token
from aauth.tokens.resource_token import create_resource_token
from aauth.tokens.agent_token import create_agent_token
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, calculate_jwk_thumbprint
from aauth.errors import TokenError, MetadataError
import httpx


class TestExtractResourceToken:
    """Tests for extract_resource_token helper."""

    def test_extract_from_valid_challenge_header(self):
        """Extract resource_token from a valid AAuth challenge header."""
        test_token = "eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUifQ.sig"
        headers = {
            "AAuth-Requirement": f'requirement=auth-token; resource-token="{test_token}"'
        }
        result = extract_resource_token(headers)
        assert result == test_token

    def test_extract_from_case_insensitive_header(self):
        """extract_resource_token is case-insensitive for header names."""
        test_token = "eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUifQ.sig"
        headers = {
            "aauth-requirement": f'requirement=auth-token; resource-token="{test_token}"'
        }
        result = extract_resource_token(headers)
        assert result == test_token

    def test_extract_from_missing_header(self):
        """extract_resource_token returns None when no AAuth header present."""
        headers = {"Content-Type": "application/json"}
        result = extract_resource_token(headers)
        assert result is None

    def test_extract_from_header_without_resource_token_param(self):
        """extract_resource_token returns None when resource-token param missing."""
        headers = {"AAuth-Requirement": "requirement=identity"}
        result = extract_resource_token(headers)
        assert result is None

    def test_extract_handles_malformed_header_gracefully(self):
        """extract_resource_token returns None on parse errors."""
        headers = {"AAuth-Requirement": "garbage_header_content"}
        result = extract_resource_token(headers)
        assert result is None


class TestExchangeResourceToken:
    """Tests for exchange_resource_token function."""

    @pytest.fixture
    def agent_keys(self):
        """Generate test agent keys."""
        agent_priv, agent_pub = generate_ed25519_keypair()
        agent_jwk = public_key_to_jwk(agent_pub)
        agent_jkt = calculate_jwk_thumbprint(agent_jwk)
        return agent_priv, agent_pub, agent_jkt

    def test_exchange_resource_token_missing_aud(self, agent_keys):
        """Raises TokenError if resource_token missing aud claim."""
        import jwt

        agent_priv, _, _ = agent_keys

        # Create JWT without aud claim
        bad_token = jwt.encode(
            {"iss": "https://ps.example", "agent": "https://agent.example"},
            agent_priv,
            algorithm="EdDSA",
        )

        async def run_test():
            with pytest.raises(TokenError, match="missing 'aud' claim"):
                await exchange_resource_token(
                    resource_token=bad_token,
                    private_key=agent_priv,
                    agent_jwt="dummy-jwt",
                )

        asyncio.run(run_test())

    def test_exchange_resource_token_malformed(self, agent_keys):
        """Raises TokenError if resource_token is not valid JWT."""
        agent_priv, _, _ = agent_keys

        async def run_test():
            with pytest.raises(TokenError, match="Cannot decode resource_token"):
                await exchange_resource_token(
                    resource_token="not-a-jwt",
                    private_key=agent_priv,
                    agent_jwt="dummy-jwt",
                )

        asyncio.run(run_test())


@pytest.mark.integration
class TestTokenExchangeIntegration:
    """Integration tests using a real PS-like endpoint."""

    def test_exchange_against_real_ps_server(self):
        """End-to-end test with a real PS-like server."""
        # Import here to avoid hard dependency unless running integration tests
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        import threading
        import uvicorn
        import time

        # Generate test keys
        agent_priv, agent_pub = generate_ed25519_keypair()
        agent_jwk = public_key_to_jwk(agent_pub)
        agent_jkt = calculate_jwk_thumbprint(agent_jwk)

        ps_priv, ps_pub = generate_ed25519_keypair()

        # Create a simple Starlette app that mimics PS behavior
        app = Starlette()

        @app.route("/.well-known/aauth-person.json", methods=["GET"])
        async def ps_metadata(request):
            return JSONResponse(
                {
                    "issuer": "http://127.0.0.1:8766",
                    "token_endpoint": "http://127.0.0.1:8766/token",
                    "jwks_uri": "http://127.0.0.1:8766/.well-known/jwks.json",
                }
            )

        @app.route("/token", methods=["POST"])
        async def token_endpoint(request):
            body = await request.json()
            # Just echo back a fake auth token
            auth_token = "eyJhbGciOiJFZERTQSIsInR5cCI6ImFhLWF1dGhydHQifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjg3NjYiLCJhdWQiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUiLCJhZ2VudCI6Imh0dHBzOi8vYWdlbnQuZXhhbXBsZSJ9.sig"
            return JSONResponse({"auth_token": auth_token})

        # Run server in background thread
        server_thread = threading.Thread(
            target=lambda: uvicorn.run(
                app,
                host="127.0.0.1",
                port=8766,
                log_level="critical",
            ),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.5)  # Give server time to start

        try:
            # Create resource token pointing to our test PS
            resource_token = create_resource_token(
                iss="http://127.0.0.1:8766",
                aud="http://127.0.0.1:8766",
                agent="https://agent.example",
                agent_jkt=agent_jkt,
                scope="data.read",
                private_key=ps_priv,
                kid="ps-key-1",
            )

            # Create agent JWT using correct signature
            agent_jwt = create_agent_token(
                iss="https://agent.example",
                sub="https://agent.example",
                cnf_jwk=agent_jwk,
                private_key=agent_priv,
                kid="agent-key-1",
            )

            # Perform the exchange
            async def run_exchange():
                return await exchange_resource_token(
                    resource_token=resource_token,
                    private_key=agent_priv,
                    agent_jwt=agent_jwt,
                )

            auth_token = asyncio.run(run_exchange())

            # Verify we got back a token
            assert auth_token is not None
            assert isinstance(auth_token, str)
            assert len(auth_token) > 0
            # Should have 3 JWT parts
            assert len(auth_token.split(".")) == 3
        finally:
            # Note: conftest will clean up the server via _server_lifecycle
            pass
