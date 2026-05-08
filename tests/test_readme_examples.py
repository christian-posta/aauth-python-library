"""Tests verifying every code example in README.md works as documented."""

import pytest
import aauth


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def agent_keys():
    """Ed25519 key pair for an agent."""
    private_key, public_key = aauth.generate_ed25519_keypair()
    return private_key, public_key


@pytest.fixture
def agent_jwk(agent_keys):
    _, public_key = agent_keys
    return aauth.public_key_to_jwk(public_key, kid="key-1")


@pytest.fixture
def agent_thumbprint(agent_jwk):
    return aauth.calculate_jwk_thumbprint(agent_jwk)


@pytest.fixture
def resource_keys():
    return aauth.generate_ed25519_keypair()


@pytest.fixture
def auth_keys():
    return aauth.generate_ed25519_keypair()


@pytest.fixture
def agent_token(agent_keys, agent_jwk):
    """A valid aa-agent+jwt for use in jwt-scheme signing."""
    private_key, _ = agent_keys
    return aauth.create_agent_token(
        iss="https://agent-server.example",
        sub="https://agent.example",
        cnf_jwk=agent_jwk,
        private_key=private_key,
        kid="key-1"
    )


# ---------------------------------------------------------------------------
# Quick Start — sign_request
# ---------------------------------------------------------------------------

class TestQuickStartSignRequest:
    """README: Quick Start — sign_request examples."""

    def test_hwk_scheme(self, agent_keys):
        """sign_request with sig_scheme='hwk' returns all three signature headers."""
        private_key, _ = agent_keys
        signed_headers = aauth.sign_request(
            method="GET",
            target_uri="https://resource.example/api/data",
            headers={},
            body=None,
            private_key=private_key,
            sig_scheme="hwk"
        )
        assert "Signature-Input" in signed_headers
        assert "Signature" in signed_headers
        assert "Signature-Key" in signed_headers
        assert "hwk" in signed_headers["Signature-Key"]

    def test_jwks_uri_scheme(self, agent_keys):
        """sign_request with sig_scheme='jwks_uri' embeds id/dwk/kid in Signature-Key."""
        private_key, _ = agent_keys
        signed_headers = aauth.sign_request(
            method="POST",
            target_uri="https://resource.example/api/data",
            headers={"Content-Type": "application/json"},
            body=b'{"key": "value"}',
            private_key=private_key,
            sig_scheme="jwks_uri",
            id="https://agent.example",
            kid="key-1",
            dwk="aauth-agent.json"
        )
        assert "Signature-Input" in signed_headers
        assert "Signature" in signed_headers
        assert "Signature-Key" in signed_headers
        assert "jwks_uri" in signed_headers["Signature-Key"]
        assert "https://agent.example" in signed_headers["Signature-Key"]

    def test_jwt_scheme(self, agent_keys, agent_token):
        """sign_request with sig_scheme='jwt' embeds the JWT in Signature-Key."""
        private_key, _ = agent_keys
        signed_headers = aauth.sign_request(
            method="GET",
            target_uri="https://resource.example/api/data",
            headers={},
            body=None,
            private_key=private_key,
            sig_scheme="jwt",
            jwt=agent_token
        )
        assert "Signature-Input" in signed_headers
        assert "Signature" in signed_headers
        assert "Signature-Key" in signed_headers
        assert "jwt" in signed_headers["Signature-Key"]


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

class TestKeyManagement:
    """README: Key Management section."""

    def test_generate_keypair(self):
        """generate_ed25519_keypair returns a usable private/public key pair."""
        private_key, public_key = aauth.generate_ed25519_keypair()
        assert private_key is not None
        assert public_key is not None

    def test_public_key_to_jwk(self, agent_keys):
        """public_key_to_jwk returns an OKP/Ed25519 JWK with the given kid."""
        _, public_key = agent_keys
        jwk = aauth.public_key_to_jwk(public_key, kid="key-1")
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["kid"] == "key-1"
        assert "x" in jwk

    def test_calculate_jwk_thumbprint(self, agent_jwk):
        """calculate_jwk_thumbprint returns a non-empty string."""
        thumbprint = aauth.calculate_jwk_thumbprint(agent_jwk)
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 0


# ---------------------------------------------------------------------------
# Signature Verification
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    """README: Signature Verification section."""

    def test_verify_signed_request(self, agent_keys):
        """verify_signature returns True for a request signed with sign_request."""
        private_key, _ = agent_keys
        method = "GET"
        target_uri = "https://resource.example/api/data"
        headers = {}
        body = None

        signed_headers = aauth.sign_request(
            method=method,
            target_uri=target_uri,
            headers=headers,
            body=body,
            private_key=private_key,
            sig_scheme="hwk"
        )
        all_headers = {**headers, **signed_headers}

        is_valid = aauth.verify_signature(
            method=method,
            target_uri=target_uri,
            headers=all_headers,
            body=body,
            signature_input_header=all_headers.get("Signature-Input"),
            signature_header=all_headers.get("Signature"),
            signature_key_header=all_headers.get("Signature-Key"),
        )
        assert is_valid is True

    def test_verify_rejects_wrong_key(self):
        """verify_signature returns False when the Signature-Key doesn't match the signature.

        Note: body content is NOT covered by default — only @method, @authority, @path,
        and signature-key are signed. Body coverage (content-digest) is opt-in via
        additional_signature_components and is intentionally not required by default.
        """
        private_key_a, _ = aauth.generate_ed25519_keypair()
        private_key_b, _ = aauth.generate_ed25519_keypair()
        method = "GET"
        target_uri = "https://resource.example/api/data"

        # Sign with key A
        signed_headers = aauth.sign_request(
            method=method,
            target_uri=target_uri,
            headers={},
            body=None,
            private_key=private_key_a,
            sig_scheme="hwk"
        )

        # Swap the Signature-Key to claim key B but keep the signature from key A
        signed_with_b = aauth.sign_request(
            method=method,
            target_uri=target_uri,
            headers={},
            body=None,
            private_key=private_key_b,
            sig_scheme="hwk"
        )
        tampered_headers = {
            "Signature-Input": signed_headers["Signature-Input"],
            "Signature": signed_headers["Signature"],
            "Signature-Key": signed_with_b["Signature-Key"],  # wrong key
        }

        is_valid = aauth.verify_signature(
            method=method,
            target_uri=target_uri,
            headers=tampered_headers,
            body=None,
            signature_input_header=tampered_headers["Signature-Input"],
            signature_header=tampered_headers["Signature"],
            signature_key_header=tampered_headers["Signature-Key"],
        )
        assert is_valid is False


# ---------------------------------------------------------------------------
# Token Creation
# ---------------------------------------------------------------------------

class TestTokenCreation:
    """README: Token Creation section."""

    def test_create_resource_token(self, resource_keys, agent_thumbprint):
        """create_resource_token returns a signed aa-resource+jwt."""
        resource_private_key, _ = resource_keys
        resource_token = aauth.create_resource_token(
            iss="https://resource.example",
            aud="https://auth.example",
            agent="https://agent.example",
            agent_jkt=agent_thumbprint,
            scope="data.read data.write",
            private_key=resource_private_key,
            kid="resource-key-1"
        )
        assert isinstance(resource_token, str)
        claims = aauth.parse_token_claims(resource_token)
        assert claims["header"]["typ"] == "aa-resource+jwt"
        assert claims["payload"]["iss"] == "https://resource.example"
        assert claims["payload"]["scope"] == "data.read data.write"

    def test_create_auth_token(self, auth_keys, agent_jwk):
        """create_auth_token returns a signed aa-auth+jwt with all required claims."""
        auth_private_key, _ = auth_keys
        auth_token = aauth.create_auth_token(
            iss="https://auth.example",
            aud="https://resource.example",
            agent="https://agent.example",
            cnf_jwk=agent_jwk,
            act={"sub": "https://agent.example"},
            scope="data.read",
            private_key=auth_private_key,
            kid="auth-key-1"
        )
        assert isinstance(auth_token, str)
        claims = aauth.parse_token_claims(auth_token)
        assert claims["header"]["typ"] == "aa-auth+jwt"
        assert claims["payload"]["agent"] == "https://agent.example"
        assert claims["payload"]["scope"] == "data.read"
        assert claims["payload"]["act"] == {"sub": "https://agent.example"}
        assert "cnf" in claims["payload"]

    def test_parse_token_claims(self, resource_keys, agent_thumbprint):
        """parse_token_claims returns header and payload dicts without verification."""
        resource_private_key, _ = resource_keys
        token = aauth.create_resource_token(
            iss="https://resource.example",
            aud="https://auth.example",
            agent="https://agent.example",
            agent_jkt=agent_thumbprint,
            scope="read",
            private_key=resource_private_key,
            kid="k1"
        )
        claims = aauth.parse_token_claims(token)
        assert "header" in claims
        assert "payload" in claims
        assert claims["header"]["typ"] == "aa-resource+jwt"
        assert claims["payload"]["iss"] == "https://resource.example"


# ---------------------------------------------------------------------------
# AAuth Header Parsing
# ---------------------------------------------------------------------------

class TestAAuthHeaderParsing:
    """README: AAuth Header Parsing section."""

    def test_parse_agent_auth_header(self):
        """parse_agent_auth_header correctly parses an auth-token challenge."""
        challenge = aauth.parse_agent_auth_header(
            'requirement=auth-token; resource-token="..."; auth-server="https://auth.example"'
        )
        assert challenge["requirement"] == "auth-token"
        assert challenge["auth_token"] is True
        assert challenge["resource_token"] == "..."
        assert challenge["auth_server"] == "https://auth.example"

    def test_parse_agent_auth_header_identity(self):
        """parse_agent_auth_header correctly parses an identity challenge."""
        challenge = aauth.parse_agent_auth_header("requirement=identity")
        assert challenge["requirement"] == "identity"
        assert challenge["identity"] is True
        assert challenge["auth_token"] is False

    def test_build_agent_auth_challenge_auth_token(self):
        """build_agent_auth_challenge returns a parseable auth-token requirement."""
        challenge_header = aauth.build_agent_auth_challenge(
            require_signature=True,
            require_identity=True,
            require_auth_token=True,
            resource_token="some-resource-token",
            auth_server="https://auth.example"
        )
        assert isinstance(challenge_header, str)
        # Round-trip: what we build should be parseable
        parsed = aauth.parse_agent_auth_header(challenge_header)
        assert parsed["requirement"] == "auth-token"

    def test_build_agent_auth_challenge_identity(self):
        """build_agent_auth_challenge with require_identity returns identity requirement."""
        challenge_header = aauth.build_agent_auth_challenge(
            require_signature=True,
            require_identity=True,
            require_auth_token=False,
        )
        assert isinstance(challenge_header, str)
        parsed = aauth.parse_agent_auth_header(challenge_header)
        assert parsed["requirement"] == "identity"


# ---------------------------------------------------------------------------
# High-Level Agent and Resource APIs
# ---------------------------------------------------------------------------

class TestAgentRequestSigner:
    """README: High-Level Agent API — AgentRequestSigner."""

    def test_sign_request_jwt_scheme(self, agent_keys, agent_token):
        """AgentRequestSigner.sign_request with sig_scheme='jwt' returns signature headers."""
        private_key, _ = agent_keys
        signer = aauth.AgentRequestSigner(
            private_key=private_key,
            agent_id="https://agent.example",
            agent_token=agent_token
        )
        signed_headers = signer.sign_request(
            method="GET",
            target_uri="https://resource.example/api/data",
            headers={},
            body=None,
            sig_scheme="jwt"
        )
        assert "Signature-Input" in signed_headers
        assert "Signature" in signed_headers
        assert "Signature-Key" in signed_headers

    def test_sign_request_hwk_scheme(self, agent_keys):
        """AgentRequestSigner.sign_request with sig_scheme='hwk' works without agent_token."""
        private_key, _ = agent_keys
        signer = aauth.AgentRequestSigner(private_key=private_key)
        signed_headers = signer.sign_request(
            method="GET",
            target_uri="https://resource.example/api/data",
            headers={},
            body=None,
            sig_scheme="hwk"
        )
        assert "Signature-Key" in signed_headers
        assert "hwk" in signed_headers["Signature-Key"]

    def test_sign_request_jwks_uri_scheme(self, agent_keys):
        """AgentRequestSigner.sign_request with sig_scheme='jwks_uri' requires agent_id."""
        private_key, _ = agent_keys
        signer = aauth.AgentRequestSigner(
            private_key=private_key,
            agent_id="https://agent.example"
        )
        signed_headers = signer.sign_request(
            method="GET",
            target_uri="https://resource.example/api/data",
            headers={},
            body=None,
            sig_scheme="jwks_uri"
        )
        assert "jwks_uri" in signed_headers["Signature-Key"]
        assert "https://agent.example" in signed_headers["Signature-Key"]

    def test_jwt_scheme_requires_agent_token(self, agent_keys):
        """AgentRequestSigner raises SignatureError when jwt scheme used without agent_token."""
        private_key, _ = agent_keys
        signer = aauth.AgentRequestSigner(private_key=private_key)
        with pytest.raises(aauth.SignatureError):
            signer.sign_request(
                method="GET",
                target_uri="https://resource.example/api/data",
                headers={},
                body=None,
                sig_scheme="jwt"
            )


class TestRequestVerifier:
    """README: High-Level Resource API — RequestVerifier."""

    def test_verify_valid_hwk_request(self, agent_keys):
        """RequestVerifier.verify_request returns valid=True for a correctly signed hwk request."""
        private_key, _ = agent_keys
        method = "GET"
        target_uri = "https://resource.example/api/data"
        headers = {}
        signed_headers = aauth.sign_request(
            method=method,
            target_uri=target_uri,
            headers=headers,
            body=None,
            private_key=private_key,
            sig_scheme="hwk"
        )
        request_headers = {**headers, **signed_headers}

        verifier = aauth.RequestVerifier(
            canonical_authorities=["resource.example"]
        )
        result = verifier.verify_request(
            method=method,
            target_uri=target_uri,
            headers=request_headers,
            body=None,
            require_identity=False,
            require_auth_token=False
        )
        assert result["valid"] is True

    def test_verify_rejects_wrong_authority(self, agent_keys):
        """RequestVerifier rejects requests whose authority is not in canonical_authorities."""
        private_key, _ = agent_keys
        method = "GET"
        target_uri = "https://resource.example/api/data"
        headers = {}
        signed_headers = aauth.sign_request(
            method=method,
            target_uri=target_uri,
            headers=headers,
            body=None,
            private_key=private_key,
            sig_scheme="hwk"
        )
        request_headers = {**headers, **signed_headers}

        verifier = aauth.RequestVerifier(
            canonical_authorities=["other.example"]
        )
        result = verifier.verify_request(
            method=method,
            target_uri=target_uri,
            headers=request_headers,
            body=None,
        )
        assert result["valid"] is False

    def test_verify_result_shape(self, agent_keys):
        """verify_request result always contains valid, agent_id, scopes keys."""
        private_key, _ = agent_keys
        method = "GET"
        target_uri = "https://resource.example/api/data"
        headers = {}
        signed_headers = aauth.sign_request(
            method=method, target_uri=target_uri,
            headers=headers, body=None,
            private_key=private_key, sig_scheme="hwk"
        )
        verifier = aauth.RequestVerifier(canonical_authorities=["resource.example"])
        result = verifier.verify_request(
            method=method, target_uri=target_uri,
            headers={**headers, **signed_headers}, body=None,
        )
        assert "valid" in result
        assert "agent_id" in result
        assert "scopes" in result
