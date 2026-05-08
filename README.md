# aauth

Python implementation of the [AAuth protocol](https://github.com/dickhardt/AAuth) — an authorization protocol for agent-to-resource access built on HTTP Message Signatures (RFC 9421) and JWT-based proof-of-possession tokens.

See the [full AAuth demo walkthrough](https://blog.christianposta.com/aauth-full-demo/) for a live exploration of the protocol flows.

## Installation

```bash
pip install aauth
```

The HTTP message signing stack ships as a separate package, **`aauth-signing`**, and is pulled in automatically.

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
import aauth

# Generate an Ed25519 key pair
private_key, public_key = aauth.generate_ed25519_keypair()

# Sign a request (pseudonymous — public key embedded in header)
signed_headers = aauth.sign_request(
    method="GET",
    target_uri="https://resource.example/api/data",
    headers={},
    body=None,
    private_key=private_key,
    sig_scheme="hwk"
)

# Sign with agent identity (JWKS-backed)
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

# Sign with an auth token
signed_headers = aauth.sign_request(
    method="GET",
    target_uri="https://resource.example/api/data",
    headers={},
    body=None,
    private_key=private_key,
    sig_scheme="jwt",
    jwt=auth_token
)
```

## Library Reference

### Key Management

```python
import aauth

private_key, public_key = aauth.generate_ed25519_keypair()
jwk = aauth.public_key_to_jwk(public_key, kid="key-1")
thumbprint = aauth.calculate_jwk_thumbprint(jwk)
```

### Signature Verification

```python
is_valid = aauth.verify_signature(
    method=request.method,
    target_uri=str(request.url),
    headers=dict(request.headers),
    body=request_body,
    signature_input_header=request.headers.get("Signature-Input"),
    signature_header=request.headers.get("Signature"),
    signature_key_header=request.headers.get("Signature-Key"),
    jwks_fetcher=my_jwks_fetcher  # required for jwks_uri/jwt schemes
)
```

### Token Creation

```python
# Resource token (resource → auth server)
resource_token = aauth.create_resource_token(
    iss="https://resource.example",
    aud="https://auth.example",
    agent="https://agent.example",
    agent_jkt=agent_thumbprint,
    scope="data.read data.write",
    private_key=resource_private_key,
    kid="resource-key-1"
)

# Auth token (auth server → agent)
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

# Parse token claims (no verification)
claims = aauth.parse_token_claims(token)
```

### AAuth Header Parsing

```python
# Parse an AAuth challenge from a resource's 401 response
challenge = aauth.parse_agent_auth_header(
    'requirement=auth-token; resource-token="..."; auth-server="https://auth.example"'
)

# Build an AAuth challenge
challenge_header = aauth.build_agent_auth_challenge(
    require_signature=True,
    require_identity=True,
    require_auth_token=True,
    resource_token=resource_token,
    auth_server="https://auth.example"
)
```

### High-Level Agent and Resource APIs

```python
# Agent-side request signer
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

# Resource-side request verifier
verifier = aauth.RequestVerifier(
    canonical_authorities=["resource.example:443"],
    jwks_fetcher=my_jwks_fetcher
)

result = verifier.verify_request(
    method="GET",
    target_uri="https://resource.example/api/data",
    headers=request_headers,
    body=request_body,
    require_identity=True,
    require_auth_token=True
)

if result["valid"]:
    print(f"Agent: {result['agent_id']}, Scopes: {result['scopes']}")
```

## Package Structure

```
aauth/
├── signing/      # HTTP Message Signing (RFC 9421)
├── keys/         # Key management and JWK operations
├── tokens/       # JWT token creation and validation
├── headers/      # AAuth header parsing and building
├── metadata/     # Metadata discovery (.well-known)
├── http/         # Deferred response helpers
├── agent/        # Agent role (signing, polling, token exchange)
└── resource/     # Resource role (challenge, verification)
```

## Testing

```bash
pytest tests/ -v
```

## Protocol

- Spec: [github.com/dickhardt/AAuth](https://github.com/dickhardt/AAuth)
- Demo: [blog.christianposta.com/aauth-full-demo](https://blog.christianposta.com/aauth-full-demo/)
- Site: [aauth.dev](https://www.aauth.dev)

## License

MIT
