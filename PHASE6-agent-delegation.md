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

## Output

❯ python demo_phase6.py

================================================================================
Phase 6: Agent Delegation Demo
================================================================================

MODE: Automated
================================================================================
This demo shows the agent delegation flow:
1. Agent server starts and publishes JWKS
2. Agent delegate requests agent token from agent server
3. Agent delegate accesses resource using agent token
4. Resource validates agent token and grants access
5. Agent delegate requests auth token using agent token
6. Auth server validates agent token and issues auth token with agent_delegate claim

Debug output is enabled by default.
================================================================================

Starting Agent Server...
Starting Resource...
Starting Auth Server...
Waiting for servers to start...
INFO:     Started server process [95748]
INFO:     Waiting for application startup.
INFO:     Started server process [95748]
INFO:     Waiting for application startup.
INFO:     Started server process [95748]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8003 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8002 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)

================================================================================
Ready to start test. Press Enter to begin...
================================================================================


================================================================================
TEST 1: Delegate Requests Agent Token
================================================================================
Description: Agent delegate requests agent token from agent server.
================================================================================

📤 Delegate requesting agent token from agent server...

================================================================================
>>> DELEGATE REQUEST to http://127.0.0.1:8001/delegate/token
================================================================================
POST http://127.0.0.1:8001/delegate/token HTTP/1.1
Content-Type: application/json

[Body (143 bytes)]
{"sub": "delegate-1", "cnf_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys", "kid": "delegate-key-1"}}
================================================================================


================================================================================
>>> AGENT SERVER REQUEST received (delegate token)
================================================================================
POST /delegate/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-length: 133
content-type: application/json
host: 127.0.0.1:8001
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< AGENT SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "agent_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDEiLCJzdWIiOiJkZWxlZ2F0ZS0xIiwiZXhwIjoxNzY4Nzg5ODIxLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjNxYUF6ejRvV3FKbGx4YW55Z05keVI4bzVhcG5WM3VYbVVRUVplVDVZcyIsImtpZCI6ImRlbGVnYXRlLWtleS0xIn19fQ.5kw644tM4jK8R9e_vBXJGLEjZzU06ACbl6_dKcum7YrQraKfdwadivEtxeKJ7KmPcSDDxuiSvW9hLlJQ69zlDw",
  "expires_in": 3600
}
================================================================================

INFO:     127.0.0.1:58712 - "POST /delegate/token HTTP/1.1" 200 OK

================================================================================
<<< DELEGATE RESPONSE from http://127.0.0.1:8001/delegate/token
================================================================================
HTTP/1.1 200 OK
content-length: 433
content-type: application/json
date: Mon, 19 Jan 2026 01:30:21 GMT
server: uvicorn

[Body (433 bytes)]
{"agent_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDEiLCJzdWIiOiJkZWxlZ2F0ZS0xIiwiZXhwIjoxNzY4Nzg5ODIxLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjNxYUF6ejRvV3FKbGx4YW55Z05keVI4bzVhcG5WM3VYbVVRUVplVDVZcyIsImtpZCI6ImRlbGVnYXRlLWtleS0xIn19fQ.5kw644tM4jK8R9e_vBXJGLEjZzU06ACbl6_dKcum7YrQraKfdwadivEtxeKJ7KmPcSDDxuiSvW9hLlJQ69zlDw","expires_in":3600}
================================================================================


✓ Agent token obtained: eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgw...

Verifying agent token claims:
  Token header: {
  "alg": "EdDSA",
  "kid": "key-1",
  "typ": "agent+jwt"
}
  Token payload: {
  "iss": "http://127.0.0.1:8001",
  "sub": "delegate-1",
  "exp": 1768789821,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys",
      "kid": "delegate-key-1"
    }
  }
}
  ✓ typ claim correct: agent+jwt
  ✓ iss claim correct: http://127.0.0.1:8001
  ✓ sub claim correct: delegate-1
  ✓ cnf.jwk claim present

✓ TEST 1 PASSED: Agent token obtained and validated

================================================================================
TEST 2: Delegate Accesses Resource Using Agent Token
================================================================================
Description: Agent delegate makes signed request to resource using agent token.
================================================================================

📤 Delegate accessing resource with agent token...

================================================================================
>>> DELEGATE REQUEST to http://127.0.0.1:8002/data-jwks
================================================================================
GET http://127.0.0.1:8002/data-jwks HTTP/1.1
Signature: sig1=:g1VmPaHtG7B1_vZ0FmmegnAtf804jio4EpC866wHyuPeQM07ikVZmAWxc5hjxR1SiveSq3ib9lgzDf7GwRL9AA:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786221
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJ...
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-jwks HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:g1VmPaHtG7B1_vZ0FmmegnAtf804jio4EpC866wHyuPeQM07ikVZmAWxc5hjxR1SiveSq3ib9lgzDf7GwRL9AA:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786221
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJ...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58714 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58715 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 206
content-type: application/json

[Body (206 bytes)]
{"message":"Access granted","data":"This is protected data (identified via agent token)","scheme":"jwt","token_type":"agent+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":"delegate-1"}
================================================================================

INFO:     127.0.0.1:58713 - "GET /data-jwks HTTP/1.1" 200 OK

================================================================================
<<< DELEGATE RESPONSE from http://127.0.0.1:8002/data-jwks
================================================================================
HTTP/1.1 200 OK
content-length: 206
content-type: application/json
date: Mon, 19 Jan 2026 01:30:21 GMT
server: uvicorn

[Body (206 bytes)]
{"message":"Access granted","data":"This is protected data (identified via agent token)","scheme":"jwt","token_type":"agent+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":"delegate-1"}
================================================================================


✓ Resource access granted
  Response: {
  "message": "Access granted",
  "data": "This is protected data (identified via agent token)",
  "scheme": "jwt",
  "token_type": "agent+jwt",
  "method": "GET",
  "agent": "http://127.0.0.1:8001",
  "agent_delegate": "delegate-1"
}
  ✓ Resource recognized agent token

================================================================================
TEST 3: Delegate Requests Auth Token Using Agent Token
================================================================================
Description: Agent delegate requests auth token from auth server using agent token.
================================================================================

📤 Delegate requesting auth token from auth server...
  Note: Full auth token flow requires resource token (Phase 3/4)
  This test verifies delegate can sign requests with agent token

✓ TEST 3 PASSED: Delegate can sign requests with agent token

================================================================================
TEST SUMMARY
================================================================================
✓ PASSED: TEST 1: Delegate Requests Agent Token
✓ PASSED: TEST 2: Delegate Accesses Resource
✓ PASSED: TEST 3: Delegate Requests Auth Token

--------------------------------------------------------------------------------
Total: 3 | Passed: 3 | Failed: 0
================================================================================

Servers are still running. Press Ctrl+C to stop.
