# AAuth Protocol Implementation

A Python implementation of the AAuth protocol for learning and understanding the protocol through hands-on coding.

## Library Installation

This project includes a reusable `aauth` Python library that can be installed and used in other projects.

### Installing in the Current Project

If you're working within this project:

```bash
# Install in editable mode (recommended for development)
pip install -e .

# Or install normally
pip install .
```

### Installing in Other Projects on the Same Computer

To use this library in other projects on the same computer:

1. **Navigate to your other project directory:**
   ```bash
   cd /path/to/your/other/project
   ```

2. **Activate your project's virtual environment:**
   ```bash
   # If using venv
   source .venv/bin/activate  # or venv/bin/activate
   
   # If using conda
   conda activate your-env-name
   ```

3. **Install the library in editable mode using the absolute path:**
   ```bash
   pip install -e /Users/christian.posta/dev/code/aauth
   ```
   
   Or if you're in a different location, use the full path to this project:
   ```bash
   pip install -e /full/path/to/aauth/project
   ```

4. **Verify the installation:**
   ```bash
   pip list | grep aauth
   python -c "import aauth; print(aauth.__file__)"
   ```

   The `__file__` should point to the source directory, confirming editable mode.

5. **Use the library in your code:**
   ```python
   import aauth
   
   # Now you can use all the library functions
   private_key, public_key = aauth.generate_ed25519_keypair()
   ```

**Note:** Editable mode (`-e`) means changes to the library source code will be immediately available in your other projects without reinstalling. This is ideal for development.

Once installed, you can import and use the library:

```python
import aauth

# Generate a key pair
private_key, public_key = aauth.generate_ed25519_keypair()

# Sign a request
signed_headers = aauth.sign_request(
    method="GET",
    target_uri="https://resource.example/api/data",
    headers={},
    body=None,
    private_key=private_key
)

# Verify a signature
is_valid = aauth.verify_signature(
    method="GET",
    target_uri="https://resource.example/api/data",
    headers=signed_headers,
    body=None,
    signature_input_header=signed_headers["Signature-Input"],
    signature_header=signed_headers["Signature"],
    signature_key_header=signed_headers["Signature-Key"]
)
```

See the [Library Usage](#library-usage) section below for more examples.

## Overview

This project implements the AAuth protocol incrementally, phase by phase. See **[DEMOS.md](DEMOS.md)** for how each `demo_phase*.py` maps to **`SPEC_UPDATED.md`** and which spec areas are not yet demoed.

- **Phase 1**: Pseudonymous flow (proof-of-possession without identity)
- **Phase 2**: Agent identity (JWKS-based identity verification)
- **Phase 3**: Autonomous authorization (full token flow)
- **Phase 4**: User delegation (202 + pending URL, interaction code, polling — SPEC_UPDATED Section 4.5.4)
- **Phase 5**: Agent is Resource (SSO and unified token flow)
- **Phase 6**: Agent Delegation (agent tokens for distributed instances)
- **Phase 7**: Token Exchange (multi-hop resource access with delegation chain)

## Quick Start

### Setup

1. Install dependencies:
```bash
# (Recommended) Use virtual environment
python3 -m venv .venv
source .venv/bin/activate


pip install -r requirements.txt

```

### Running Demos

#### Phase 1: Pseudonymous Flow

Demonstrates basic proof-of-possession without identity using `sig=hwk` scheme:

```bash
python demo_phase1.py
```

#### Phase 2: Agent Identity via JWKS

Demonstrates agent identity verification using `sig=jwks` scheme:

```bash
python demo_phase2.py
```

#### Phase 3: Autonomous Authorization

Demonstrates complete token flow without user interaction:

```bash
python demo_phase3.py
```

#### Phase 4: User Delegation

Demonstrates user-authorized access: resource challenge, token endpoint **202** + **pending URL**, user interaction at **`/interact`**, agent **polling** for `auth_token` (no OAuth authorization code):

**Automated mode** (uses user simulator):
```bash
python demo_phase4.py
```

**Manual mode** (browser-based testing):
```bash
python demo_phase4.py --manual
```

#### Phase 5: Agent is Resource

Demonstrates agent authenticating users to itself for SSO and API access:

**Automated mode** (uses user simulator):
```bash
python demo_phase5.py
```

**Manual mode** (browser-based testing):
```bash
python demo_phase5.py --manual
```

#### Phase 6: Agent Delegation

Demonstrates agent delegation where agent servers issue agent tokens to delegates:

**Automated mode**:
```bash
python demo_phase6.py
```

#### Phase 7: Token Exchange

Demonstrates multi-hop resource access where a resource exchanges an upstream auth token to access a downstream resource:

**Automated mode**:
```bash
python demo_phase7.py
```

## Testing

Run all tests:
```bash
pytest tests/ -v
```

Run tests for a specific phase:
```bash
pytest tests/test_phase1.py -v
pytest tests/test_phase2.py -v
pytest tests/test_phase3.py -v
pytest tests/test_phase4.py -v
pytest tests/test_phase5.py -v
pytest tests/test_phase6.py -v
pytest tests/test_phase7.py -v
```

## Phase Overview

### Phase 1: Pseudonymous Flow
- Agent signs requests with `sig=hwk` (public key in header)
- Resource validates signatures
- No tokens, no identity - just signature verification

See [PHASE1-pop-hwk.md](PHASE1-pop-hwk.md) for detailed documentation.

### Phase 2: Agent Identity via JWKS
- Agent publishes metadata at `/.well-known/aauth-agent`
- Agent publishes JWKS at `/jwks.json`
- Resource can verify agent identity using `sig=jwks` scheme
- Separate endpoints (`/data-hwk`, `/data-jwks`) for both schemes

See [PHASE2-identity-jwks.md](PHASE2-identity-jwks.md) for detailed documentation.

### Phase 3: Autonomous Authorization
- Resources issue resource tokens when agents request access
- Agents present resource tokens to auth servers
- Auth servers validate resource tokens and issue auth tokens
- Agents use auth tokens to access protected resources
- Complete token flow without user interaction

See [PHASE3-autonomous-authz.md](PHASE3-autonomous-authz.md) for detailed documentation.

### Phase 4: User Delegation
- Resource returns 401 with resource token; agent POSTs to auth server `token_endpoint`
- When consent is required, auth server returns **202** + `Location` (pending URL) + interaction **code**
- User completes login/consent at **`/interact`**; agent **polls** pending URL until **200** with `auth_token`
- No authorization code: token is delivered only via signed polling (SPEC_UPDATED Sections 10, 19.2)

See [PHASE4-user-delegation.md](PHASE4-user-delegation.md) for detailed documentation.

### Phase 5: Agent is Resource
- Agent requests authorization directly with `scope` (no `resource_token`)
- Agent identifier matches resource identifier (agent authenticates users to itself)
- Auth token has `aud` = agent identifier and `agent` claim omitted
- Unified token serves both SSO (user identity) and API access purposes
- Solves OIDC limitation where ID tokens and access tokens are separate

See [PHASE5-agent-is-resource.md](PHASE5-agent-is-resource.md) for detailed documentation.

### Phase 6: Agent Delegation
- Agent servers issue agent tokens (`agent+jwt`) to agent delegates
- Delegates use `scheme=jwt` with agent tokens to sign requests
- Resources and auth servers validate agent tokens per SPEC.md Section 5.7
- Delegates share agent server's identity but use ephemeral keys
- Delegate identifier (`sub`) persists across key rotations
- Auth tokens include `agent_delegate` claim when issued to delegates

See [PHASE6-agent-delegation.md](PHASE6-agent-delegation.md) for detailed documentation.

### Phase 7: Token Exchange
- Resources can act as agents to access downstream resources
- Upstream auth tokens are exchanged for downstream auth tokens
- Downstream auth server validates upstream token and federation trust
- Exchanged tokens include `act` claim showing the delegation chain
- User context (`sub`) is preserved through the chain
- Enables autonomous multi-hop resource access

See [PHASE7-token-exchange.md](PHASE7-token-exchange.md) for detailed documentation.

## Running Individual Participants

### Run Resource Server:
```bash
python -m participants.resource
```

### Run Agent:
```bash
python -m participants.agent
```

### Run Auth Server:
```bash
python -m participants.auth_server
```

## Library Usage

The `aauth` library provides a framework-agnostic implementation of the AAuth protocol. Here are some common usage patterns:

### Key Generation

```python
import aauth

# Generate Ed25519 key pair
private_key, public_key = aauth.generate_ed25519_keypair()

# Convert to JWK format
jwk = aauth.public_key_to_jwk(public_key, kid="key-1")

# Calculate JWK thumbprint
thumbprint = aauth.calculate_jwk_thumbprint(jwk)
```

### HTTP Message Signing

```python
import aauth

# Sign a request with hwk scheme (pseudonymous)
signed_headers = aauth.sign_request(
    method="GET",
    target_uri="https://resource.example/api/data",
    headers={"Host": "resource.example"},
    body=None,
    private_key=private_key,
    sig_scheme="hwk"
)

# Sign with jwks scheme (agent identity)
signed_headers = aauth.sign_request(
    method="POST",
    target_uri="https://resource.example/api/data",
    headers={"Content-Type": "application/json"},
    body=b'{"key": "value"}',
    private_key=private_key,
    sig_scheme="jwks",
    id="https://agent.example",
    kid="key-1"
)

# Sign with jwt scheme (using auth token)
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

### Signature Verification

```python
import aauth

# Verify a signature
is_valid = aauth.verify_signature(
    method=request.method,
    target_uri=str(request.url),
    headers=dict(request.headers),
    body=request_body,
    signature_input_header=request.headers.get("Signature-Input"),
    signature_header=request.headers.get("Signature"),
    signature_key_header=request.headers.get("Signature-Key"),
    jwks_fetcher=my_jwks_fetcher  # Required for jwks/jwt schemes
)
```

### Token Creation and Validation

```python
import aauth

# Create a resource token
resource_token = aauth.create_resource_token(
    iss="https://resource.example",
    aud="https://auth.example",
    agent="https://agent.example",
    agent_jkt=agent_thumbprint,
    scope="data.read data.write",
    private_key=resource_private_key,
    kid="resource-key-1"
)

# Create an auth token
auth_token = aauth.create_auth_token(
    iss="https://auth.example",
    aud="https://resource.example",
    agent="https://agent.example",
    cnf_jwk=agent_jwk,
    scope="data.read",
    private_key=auth_private_key,
    kid="auth-key-1"
)

# Verify an agent token
claims = aauth.verify_agent_token(
    token=agent_token,
    jwks_fetcher=my_jwks_fetcher,
    expected_aud="https://resource.example"
)

# Parse token claims (without verification)
claims = aauth.parse_token_claims(token)
```

### Agent-Auth Header Parsing

```python
import aauth

# Parse Agent-Auth challenge header
challenge = aauth.parse_agent_auth_header(
    "httpsig; identity=?1; auth-token; resource_token=\"...\"; auth_server=\"https://auth.example\""
)

# Build Agent-Auth challenge
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
import aauth

# Agent request signer
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

# Resource request verifier
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
    print(f"Agent ID: {result['agent_id']}")
    print(f"Scopes: {result['scopes']}")
```

### Framework Integration

The library is framework-agnostic. Here's an example for FastAPI:

```python
from fastapi import FastAPI, Request
from aauth import RequestVerifier, AAuthRequest

app = FastAPI()
verifier = RequestVerifier(canonical_authorities=["api.example.com"])

@app.get("/protected")
async def protected_endpoint(request: Request):
    # Convert FastAPI request to AAuthRequest
    aauth_req = AAuthRequest.from_fastapi_request(request)
    
    # Verify signature
    result = verifier.verify_request(
        method=aauth_req.method,
        target_uri=str(request.url),
        headers=dict(request.headers),
        body=await request.body()
    )
    
    if not result["valid"]:
        return {"error": result["error"]}, 401
    
    return {"data": "protected resource", "agent": result["agent_id"]}
```

## Project Structure

```
aauth/
├── aauth/             # Main library package (installable)
│   ├── signing/      # HTTP Message Signing (RFC 9421)
│   ├── keys/         # Key management and JWK operations
│   ├── tokens/       # JWT token handling
│   ├── headers/      # HTTP header parsing/building
│   ├── metadata/     # Metadata discovery
│   ├── http/         # HTTP abstraction layer
│   ├── agent/        # Agent role implementation
│   └── resource/     # Resource role implementation
├── core/             # Legacy core utilities (deprecated, use aauth.*)
├── participants/     # Protocol participants (demo implementations)
├── flows/           # Flow implementations
└── tests/           # Test suite
```

## Documentation

- [PHASE1-pop-hwk.md](PHASE1-pop-hwk.md) - Phase 1 implementation details
- [PHASE2-identity-jwks.md](PHASE2-identity-jwks.md) - Phase 2 implementation details
- [PHASE3-autonomous-authz.md](PHASE3-autonomous-authz.md) - Phase 3 implementation details
- [PHASE4-user-delegation.md](PHASE4-user-delegation.md) - Phase 4 implementation details
- [PHASE5-agent-is-resource.md](PHASE5-agent-is-resource.md) - Phase 5 implementation details
- [PHASE6-agent-delegation.md](PHASE6-agent-delegation.md) - Phase 6 implementation details
- [PHASE7-token-exchange.md](PHASE7-token-exchange.md) - Phase 7 implementation details
- [SPEC.md](SPEC.md) - AAuth protocol specification (exploratory / older narrative)
- [SPEC_UPDATED.md](SPEC_UPDATED.md) - Draft-aligned protocol text used for current implementation
- [DEMOS.md](DEMOS.md) - `demo_phase*.py` ↔ spec mapping and known gaps
- [PLAN.md](PLAN.md) - Overall implementation plan


