# Phase 6: Agent Delegation

Phase 6 implements agent delegation (SPEC.md Section 3.3 and Section 5) where agent servers issue agent tokens to agent delegates, enabling distributed application instances to share a single agent identity while using ephemeral keys. Delegates use `scheme=jwt` with agent tokens to sign requests, and resources/auth servers validate these tokens.

## Flow Description

### Automated Flow

1. **Agent server starts** and publishes JWKS at `/.well-known/aauth-agent`
   - Agent server has its own agent identifier and signing key
   
2. **Agent delegate requests agent token** (`POST /delegate/token`)
   - Delegate generates ephemeral key pair
   - Delegate sends public key (`cnf_jwk`) and delegate identifier (`sub`) to agent server
   - Agent server issues agent token (agent+jwt) binding delegate's key to agent server's identity
   
3. **Agent delegate accesses resource** using agent token
   - Signs request with `scheme=jwt` and agent token
   - Resource validates agent token:
     - Verifies agent token signature using agent server's JWKS
     - Extracts delegate's key from `cnf.jwk`
     - Verifies HTTPSig signature using delegate's key
   - Resource grants access (identified request)
   
4. **Agent delegate requests auth token** using agent token
   - Signs request to auth server with `scheme=jwt` and agent token
   - Auth server validates agent token
   - Auth server issues auth token with `agent_delegate` claim

## Key Features

### Agent Token (agent+jwt)

- **Token Type**: `typ: "agent+jwt"` (distinct from `auth+jwt`)
- **Required Claims**:
  - `iss`: Agent server identifier (HTTPS URL) - also the agent identifier
  - `sub`: Agent delegate identifier (persists across key rotations)
  - `exp`: Expiration timestamp
  - `cnf.jwk`: Agent delegate's public signing key
- **Optional Claims**:
  - `aud`: Audience restriction

### Delegation Model

- **Agent Server**: Uses `scheme=jwks` directly (no agent token needed)
- **Agent Delegate**: Uses `scheme=jwt` with agent token
- **Shared Identity**: Both share the same agent identifier (from `iss` claim)
- **Persistent Delegate Identity**: `sub` claim persists across key rotations, enabling refresh token continuity

### Two-Step Validation

When a delegate presents `scheme=jwt` with an agent token:

1. **JWT Validation**: Verify agent token signature using agent server's JWKS
   - Establishes agent identity (from `iss`)
   - Establishes delegate identity (from `sub`)
   - Verifies token expiration
2. **HTTPSig Verification**: Verify request signature using delegate's key (from `cnf.jwk`)
   - Proves proof-of-possession of delegate's private key

Both validations must succeed for the request to be authenticated.

### Key Rotation

- **Ephemeral Keys**: Delegate generates new key pair at startup
- **Persistent Identity**: Delegate identifier (`sub`) remains the same across key rotations
- **New Agent Token**: Delegate requests new agent token with same `sub` but new `cnf.jwk`
- **Refresh Token Continuity**: Refresh tokens remain valid across key rotations (bound to agent + `sub`)

## Token Claims Structure

**Agent Token (agent+jwt):**
```json
{
  "iss": "https://agent.example",      // Agent server identifier
  "sub": "spiffe://example.com/workload/api-service",  // Delegate identifier
  "exp": 1730218200,
  "cnf": {
    "jwk": {                            // Delegate's public key
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  }
}
```

**Auth Token with Agent Delegate (auth+jwt):**
```json
{
  "iss": "https://auth.example",
  "aud": "https://resource.example",
  "agent": "https://agent.example",    // Agent server identifier
  "agent_delegate": "spiffe://example.com/workload/api-service",  // Delegate identifier
  "scope": "data.read",
  "cnf": {
    "jwk": {                            // Delegate's public key
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  },
  "exp": 1730221200
}
```

## Testing

### Automated Testing
```bash
python demo_phase6.py
```

This runs the complete delegation flow:
1. Delegate requests agent token
2. Delegate accesses resource using agent token
3. Delegate requests auth token using agent token

### Unit Tests
```bash
pytest tests/test_phase6.py -v
```

## What Was Implemented

### Core Components

1. **Token Creation** (`core/tokens.py`)
   - `create_agent_token()`: Creates agent tokens with required claims
   - `verify_agent_token()`: Validates agent tokens per SPEC.md Section 5.7

2. **JWT Type Detection** (`core/httpsig.py`)
   - Updated `verify_signature()` to check JWT `typ` claim
   - Routes to `verify_agent_token()` for `agent+jwt`
   - Routes to existing auth token validation for `auth+jwt`

3. **Agent Server** (`participants/agent.py`)
   - Added `POST /delegate/token` endpoint to issue agent tokens
   - Tracks issued tokens by `sub` for delegation management

4. **Agent Delegate** (`participants/agent_delegate.py`)
   - New `AgentDelegate` class
   - `request_agent_token()`: Requests agent token from agent server
   - `sign_request()`: Signs requests using agent token (`scheme=jwt`)
   - `request_resource()`: Makes signed requests to resources

5. **Resource** (`participants/resource.py`)
   - Updated `_handle_protected_request()` to validate agent tokens
   - Added `_verify_agent_token()` method
   - Extracts agent identity from `iss` claim (agent server identifier)

6. **Auth Server** (`participants/auth_server.py`)
   - Updated `_handle_token_request()` to accept and validate agent tokens
   - Updated `_handle_code_exchange()` to support agent tokens
   - Includes `agent_delegate` claim in issued auth tokens

7. **Demo Script** (`demo_phase6.py`)
   - Interactive demonstration of delegation flow
   - Verifies agent token claims and resource access

8. **Tests** (`tests/test_phase6.py`)
   - Unit tests for agent token creation and validation
   - Integration test for delegate resource access

## Use Cases

### Mobile Applications

A mobile app with millions of installations uses agent delegation:
- Each installation has a unique delegate identifier (`sub`)
- Each installation generates its own ephemeral key pair
- Agent server issues agent tokens binding each installation's key to the app's identity
- No shared secrets needed across installations

### Server Workloads

Distributed server workloads use agent delegation:
- Each workload instance has a unique delegate identifier (e.g., SPIFFE ID)
- Each instance generates ephemeral keys
- Agent server issues agent tokens binding each instance's key to the service identity
- Enables rapid key rotation without affecting refresh tokens

### Desktop/CLI Applications

Desktop and CLI tools use agent delegation:
- Each installation has a persistent delegate identifier
- Keys can be stored securely or generated ephemerally
- Agent server issues agent tokens enabling distributed instances
- Refresh tokens remain valid across key rotations

## Differences from Previous Phases

| Aspect | Previous Phases | Phase 6 |
|--------|----------------|---------|
| **Agent Identity** | Agent server uses `scheme=jwks` | Agent delegate uses `scheme=jwt` with agent token |
| **Token Type** | `auth+jwt` (auth tokens) | `agent+jwt` (agent tokens) |
| **Identity Source** | Agent server's JWKS | Agent token's `iss` claim |
| **Key Binding** | Agent server's key | Delegate's key (in `cnf.jwk`) |
| **Use Case** | Single agent instance | Distributed instances with shared identity |
| **Auth Token Claims** | `agent` claim only | `agent` + `agent_delegate` claims |

## Implementation Notes

- **Backward compatibility**: Existing auth token flows (Phase 3/4/5) continue to work
- **Token type detection**: JWT validation checks `typ` claim to route to appropriate validator
- **Two-step validation**: JWT validation first (establishes identity), then HTTPSig verification (proof-of-possession)
- **Delegate identity**: `sub` claim persists across key rotations, enabling refresh token continuity
- **Agent identifier**: Both agent server and delegate share same `agent` identifier (from `iss` claim)
- **Demo simplicity**: Agent server endpoint uses simple authentication for demo purposes (real deployments would use SPIFFE, mTLS, etc.)

## Security Considerations

- **Short-lived tokens**: Agent servers should issue short-lived agent tokens (default: 1 hour)
- **Key rotation**: Delegates should rotate keys frequently (ephemeral keys at restart or persisted keys per policy)
- **Token tracking**: Agent servers track issued tokens by `sub` for delegation management
- **Audience restriction**: Agent tokens can include `aud` claim to restrict which resources/auth servers can accept them
- **Two-step validation**: Both JWT validation and HTTPSig verification must succeed for authentication

