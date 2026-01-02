# Phase 3: Autonomous Authorization

![Phase 3 Demo Screenshot](images/demo3.png)

Phase 3 implements the autonomous authorization flow where agents obtain authorization from auth servers without user interaction. Resources issue resource tokens, agents present them to auth servers, and auth servers issue auth tokens for resource access.


## How It Works

### Architecture Flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant R as Resource
    participant AS as Auth Server
    
    Note over A,R: Step 1: Agent requests resource
    A->>R: GET /data-auth (sig=jwks, no auth token)
    R->>R: Verify sig=jwks (no auth token present)
    R->>R: Issue resource token
    R-->>A: 401 Unauthorized (Agent-Auth: auth-token, resource_token, auth_server)
    
    Note over A,AS: Step 2: Agent requests auth token
    A->>A: Parse resource_token and auth_server
    A->>AS: POST /agent/token (request_type=auth, resource_token, sig=jwks)
    AS->>AS: Verify agent signature
    AS->>AS: Validate resource token
    AS->>AS: Evaluate policy (allow-all)
    AS->>AS: Issue auth token
    AS-->>A: 200 OK (auth_token, expires_in=3600)
    
    Note over A,R: Step 3: Agent retries with auth token
    A->>A: Store auth token
    A->>R: GET /data-auth (sig=jwt with auth token)
    R->>R: Extract JWT from Signature-Key
    R->>R: Validate auth token (typ, exp, signature, cnf.jwk)
    R->>R: Verify HTTPSig with cnf.jwk key
    R-->>A: 200 OK (Access granted)
```

### Token Types

#### Resource Token (resource+jwt)

**Purpose**: Binds agent identity and access request to resource identity.

**Claims**:
- `iss`: Resource identifier (HTTPS URL)
- `aud`: Auth server identifier (HTTPS URL)
- `agent`: Agent identifier (HTTPS URL)
- `agent_jkt`: JWK Thumbprint of agent's signing key (RFC 7638)
- `scope`: Space-separated scope values
- `exp`: Expiration timestamp

**Signed by**: Resource's private key

**Example**:
```json
{
  "typ": "resource+jwt",
  "alg": "EdDSA",
  "kid": "resource-key-1"
}
{
  "iss": "https://resource.example",
  "aud": "https://auth.example",
  "agent": "https://agent.example",
  "agent_jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "scope": "data.read data.write",
  "exp": 1730221200
}
```

#### Auth Token (auth+jwt)

**Purpose**: Authorizes agent to access specific resource.

**Claims**:
- `iss`: Auth server identifier (HTTPS URL)
- `aud`: Resource identifier (HTTPS URL)
- `agent`: Agent identifier (HTTPS URL)
- `cnf.jwk`: Agent's public signing key (JWK format)
- `scope`: Authorized scope values
- `exp`: Expiration timestamp
- `sub`: Optional user identifier (Phase 4)
- `agent_delegate`: Optional agent delegate identifier (Phase 4)

**Signed by**: Auth server's private key

**Example**:
```json
{
  "typ": "auth+jwt",
  "alg": "EdDSA",
  "kid": "auth-key-1"
}
{
  "iss": "https://auth.example",
  "aud": "https://resource.example",
  "agent": "https://agent.example",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  },
  "scope": "data.read data.write",
  "exp": 1730221200
}
```

### Autonomous Authorization Flow

1. **Agent requests resource** (without auth token)
   - Agent signs request with `sig=jwks` (agent identity)
   - Resource detects missing auth token

2. **Resource issues resource token challenge**
   - Resource creates resource token binding:
     - Agent identity (from signature)
     - Agent's current signing key (via JWK thumbprint)
     - Requested scope
   - Resource returns 401 with Agent-Auth header containing:
     - `resource_token`: Signed resource token
     - `auth_server`: Auth server identifier

3. **Agent requests auth token**
   - Agent parses `resource_token` and `auth_server` from challenge
   - Agent signs request to auth server with `sig=jwks`
   - Agent includes `resource_token` in request body

4. **Auth server validates and issues tokens**
   - Auth server verifies agent's HTTPSig signature
   - Auth server validates resource token:
     - Signature verification (using resource's JWKS)
     - Claim validation (iss, aud, agent, agent_jkt, exp)
   - Auth server evaluates policy (Phase 3: allow-all)
   - Auth server issues auth token with:
     - Agent's public key in `cnf.jwk`
     - Authorized scope from resource token
   - Auth server returns auth token + refresh token

5. **Agent retries resource request**
   - Agent stores auth token
   - Agent retries original request with `sig=jwt` and auth token
   - Resource validates auth token, verifies message signature from `jwt.cnf` and grants access

## Running Phase 3

### Automated Tests

Run the Phase 3 test suite:

```bash
pytest tests/test_phase3.py -v
```

This includes:
- Token generation and validation tests
- JWK thumbprint calculation tests
- Auth server endpoint tests
- End-to-end autonomous flow tests
- Error case tests (expired tokens, invalid signatures)

### Demo Script

Run the Phase 3 demo:

```bash
python demo_phase3.py
```

This demonstrates:
- Complete autonomous authorization flow
- Resource token issuance
- Auth token request and issuance
- Resource access with auth token
- Comprehensive debug output

### Manual Testing

#### Step 1: Start Servers

**Terminal 1 - Resource**:
```bash
python -c "from participants.resource import Resource; Resource('http://127.0.0.1:8002', port=8002, auth_server='http://127.0.0.1:8003').run()"
```

**Terminal 2 - Auth Server**:
```bash
python -c "from participants.auth_server import AuthServer; AuthServer('http://127.0.0.1:8003', port=8003).run()"
```

#### Step 2: Test Autonomous Flow

**Terminal 4 - Python REPL**:
```python
import asyncio
from participants.agent import Agent

async def test():
    agent = Agent("http://127.0.0.1:8001", port=8001)
    
    # Request resource (will automatically handle challenge)
    response = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-auth",
        method="GET",
        sig_scheme="jwks"
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {response.json()}")
        print("✓ SUCCESS")
    else:
        print(f"Error: {response.text}")

asyncio.run(test())
```

#### Expected Output

You should see comprehensive debug output showing:
- Agent request with `sig=jwks`
- Resource token issuance
- Agent-Auth challenge with resource_token
- Auth token request to auth server
- Resource token validation
- Policy evaluation
- Auth token issuance
- Retry with auth token
- Auth token validation
- Successful access

## Debug Output

Phase 3 includes comprehensive debug output enabled by default. All debug output goes to `stderr` with clear prefixes:

- `DEBUG TOKEN:` - Token generation and validation
- `DEBUG AUTH:` - Auth server operations
- `DEBUG RESOURCE:` - Resource operations
- `DEBUG AGENT:` - Agent operations
- `DEBUG VERIFY:` - HTTPSig verification
- `DEBUG HTTPSIG:` - HTTPSig operations

### Environment Variables

Debug output is controlled via environment variables. Default values are configured in `core/__init__.py`:
- `AAUTH_DEBUG`: Defaults to `"0"` (disabled) - Controls detailed signature verification debug output
- `AAUTH_DEBUG_HTTP`: Defaults to `"1"` (enabled) - Controls HTTP-level request/response logging
- `AAUTH_DEBUG_JWT_TOKEN`: Defaults to `"1"` (enabled) - Controls JWT token decoding/printing in demo flows

### AAUTH_DEBUG

Enable detailed signature verification debug output:

```bash
AAUTH_DEBUG=1 python demo_phase3.py
```

**Note:** By default, `AAUTH_DEBUG` is disabled (`"0"`). Set it to `"1"` to enable.

This shows:
- Signature base construction
- Component parsing
- Timestamp validation
- Key extraction and matching
- JWKS fetching steps (for `sig=jwks`)
- Token signature verification
- Signature verification results

### AAUTH_DEBUG_HTTP

HTTP-level request/response logging (curl-like format):

```bash
AAUTH_DEBUG_HTTP=1 python demo_phase3.py
```

**Note:** By default, `AAUTH_DEBUG_HTTP` is enabled (`"1"`). Set it to `"0"` to disable.

This shows:
- Full HTTP request headers and bodies
- Full HTTP response headers and bodies
- Both for agent→resource requests
- Both for agent→auth server requests
- Both for resource→agent metadata/JWKS fetches

### AAUTH_DEBUG_JWT_TOKEN

JWT token decoding and printing in demo flows:

```bash
AAUTH_DEBUG_JWT_TOKEN=1 python demo_phase3.py
```

**Note:** By default, `AAUTH_DEBUG_JWT_TOKEN` is enabled (`"1"`). Set it to `"0"` to disable.

When enabled, the demo script will print decoded resource tokens and auth tokens showing:
- Token header (typ, alg, kid)
- Token payload (iss, aud, agent, scope, exp, cnf.jwk, etc.)
- Formatted JSON output for easy inspection

### Combined Debug

Enable all debug modes:

```bash
AAUTH_DEBUG=1 AAUTH_DEBUG_HTTP=1 AAUTH_DEBUG_JWT_TOKEN=1 python demo_phase3.py
```

**Note:** Since `AAUTH_DEBUG_HTTP` and `AAUTH_DEBUG_JWT_TOKEN` are enabled by default, you only need to set `AAUTH_DEBUG=1` to enable all modes.

### Example Debug Output

**Token Generation**:
```
DEBUG TOKEN: Creating resource token:
DEBUG TOKEN:   Header: {
  "typ": "resource+jwt",
  "alg": "EdDSA",
  "kid": "resource-key-1"
}
DEBUG TOKEN:   Payload: {
  "iss": "http://127.0.0.1:8002",
  "aud": "http://127.0.0.1:8003",
  "agent": "http://127.0.0.1:8001",
  "agent_jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "scope": "data.read",
  "exp": 1730221200
}
```

**Auth Server Policy Evaluation**:
```
DEBUG AUTH: Evaluating policy:
DEBUG AUTH:   Agent: http://127.0.0.1:8001
DEBUG AUTH:   Resource: http://127.0.0.1:8002
DEBUG AUTH:   Scope: data.read
DEBUG AUTH:   Policy result: {
  "allowed": true,
  "reason": "Autonomous authorization granted (Phase 3: allow-all policy)"
}
```

**Agent Challenge Handling**:
```
DEBUG AGENT: Received 401 response, checking Agent-Auth header
DEBUG AGENT: Parsing Agent-Auth header: httpsig; auth-token; resource_token="eyJhbGc..."; auth_server="http://127.0.0.1:8003"
DEBUG AGENT:   Extracted resource_token: eyJhbGc...
DEBUG AGENT:   Extracted auth_server: http://127.0.0.1:8003
DEBUG AGENT: Requesting auth token from auth server
```

## Key Design Decisions

1. **Policy Evaluation**: Phase 3 uses simple allow-all policy for autonomous authorization. Phase 4 will add user consent and more complex policies.

2. **Token Expiration**:
   - Resource tokens: 10 minutes (short-lived)
   - Auth tokens: 1 hour (medium-lived)
   - Refresh tokens: 24 hours (optional for Phase 3)

3. **Automatic Challenge Handling**: Agent's `request_resource()` automatically handles 401 challenges, requests auth tokens, and retries with auth token. This simplifies the API for agents.

4. **Debug by Default**: All debug output is enabled by default to aid learning. Set `AAUTH_DEBUG=0` or `AAUTH_DEBUG_HTTP=0` to disable.

5. **JWK Thumbprint**: Uses RFC 7638 canonical JSON serialization for consistent thumbprint calculation across implementations.

## Success Criteria

- ✅ Resource issues resource tokens when agent requests access
- ✅ Auth server validates resource tokens and issues auth tokens
- ✅ Agent can use auth tokens to access protected resources
- ✅ All token signatures and claims are properly validated
- ✅ End-to-end autonomous flow works without user interaction
- ✅ Comprehensive debug output shows all operations
- ✅ All tests pass
- ✅ Demo script successfully demonstrates the flow


## What Was Implemented

### Core Components

1. **Token Module** (`core/tokens.py`)
   - `create_resource_token()` - Generates resource+jwt tokens per AAuth spec Section 6
   - `create_auth_token()` - Generates auth+jwt tokens per AAuth spec Section 7
   - `verify_token()` - Verifies JWT signatures and claims
   - `calculate_jwk_thumbprint()` - RFC 7638 thumbprint calculation for agent_jkt claim
   - `parse_token_claims()` - Parses token claims without verification
   - Comprehensive debug output for all token operations

2. **Auth Server** (`participants/auth_server.py`)
   - Complete auth server implementation
   - `/.well-known/aauth-issuer` metadata endpoint (Section 8.2)
   - `/jwks.json` endpoint for signing keys
   - `/agent/token` endpoint for autonomous authorization (Section 9.3)
   - Resource token validation (Section 6.5)
   - Policy evaluation (simple allow-all for Phase 3)
   - Auth token issuance
   - Comprehensive debug output

3. **Resource Updates** (`participants/resource.py`)
   - Resource token issuance when agent requests access without auth token
   - Auth token validation when agent presents `sig=jwt` with auth token
   - `/.well-known/aauth-resource` metadata endpoint (Section 8.3)
   - `/jwks.json` endpoint for resource signing keys
   - `/data-auth` endpoint that requires auth token
   - Agent-Auth challenge with `resource_token` and `auth_server` parameters
   - Comprehensive debug output

4. **Agent Updates** (`participants/agent.py`)
   - Auth challenge handling (parses `resource_token` and `auth_server` from Agent-Auth header)
   - Auth token request to auth server
   - Token storage (`auth_token`, `refresh_token`)
   - `sig=jwt` support with auth token in Signature-Key header
   - Automatic challenge handling and retry in `request_resource()`
   - Comprehensive debug output

5. **HTTPSig Updates** (`core/httpsig.py`)
   - `sig=jwt` verification support
   - JWT extraction from Signature-Key header
   - Token validation (typ check, exp check, signature verification)
   - Key derivation from `cnf.jwk` claim
   - Comprehensive debug output

6. **Metadata Updates** (`core/metadata.py`)
   - `generate_resource_metadata()` - Generates resource metadata (Section 8.3)
   - `generate_auth_metadata()` - Generates auth server metadata (Section 8.2)
   - `fetch_resource_metadata()` - Fetches resource metadata
   - `fetch_auth_metadata()` - Fetches auth server metadata

7. **Flow Orchestrator** (`flows/autonomous.py`)
   - `run_autonomous_flow()` - Orchestrates complete autonomous authorization flow