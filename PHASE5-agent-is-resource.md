# Phase 5: Agent is Resource

Phase 5 implements the "Agent is Resource" flow (SPEC.md Section 3.5) where an agent authenticates users to itself for both SSO and API access. The agent requests authorization directly with `scope` (no `resource_token`), and the returned auth token can be used to verify user identity and by agent delegates to call the agent's APIs.

## Flow Description

### Automated Flow (with User Simulator)

1. **Agent requests self-authorization** (`POST /agent/token`)
   - Provides `scope` directly (no `resource_token`)
   - Auth server validates agent signature
   - Auth server evaluates policy → requires user consent
   - Auth server returns `request_token` instead of `auth_token`
   
2. **Agent handles request_token**
   - Constructs authorization URL: `/agent/auth?request_token=...&redirect_uri=...`
   - Uses user simulator to complete flow:
     - GET `/agent/auth` → Login page
     - POST `/agent/auth` (login) → Consent page
     - POST `/agent/auth` (consent) → Redirect with authorization code
   
3. **Agent exchanges code** (`POST /agent/token` with `request_type=code`)
   - Presents authorization code with signed request
   - Auth server validates code and issues auth token with:
     - `aud` = agent identifier (agent is the resource)
     - `agent` claim **omitted** (per SPEC.md Section 7.3)
     - `sub` = user identifier
     - `scope` = requested scope
     - `cnf.jwk` = agent's signing key
   
4. **Verify auth token claims**
   - Token can be used for SSO (verify user identity from `sub` claim)
   - Token can be used for API access (agent delegates can use it)

### Manual Flow (Browser-Based)

Same as automated flow, but:
- Step 2 is performed manually by the user in a browser
- User opens authorization URL, authenticates, and grants consent
- Agent's `/callback` endpoint receives the redirect
- Agent automatically exchanges code for tokens

## Key Features

### Direct Authorization Request

- Agent provides `scope` or `auth_request_url` directly (no `resource_token`)
- Auth server validates agent signature and uses agent identifier as resource identifier
- Exactly one of `resource_token`, `scope`, or `auth_request_url` must be provided

### Unified Auth Token

- Single token serves both SSO and API access purposes
- `aud` claim = agent identifier (agent is the resource)
- `agent` claim omitted (per SPEC.md Section 7.3: "When the agent uses the auth server for SSO... `aud` is the agent identifier and this claim is omitted")
- `sub` claim = user identifier (for SSO)
- `scope` claim = authorized scopes (for API access)

### Token Claims Structure

**When agent is resource (Phase 5):**
```json
{
  "iss": "https://auth.example",
  "aud": "https://agent.example",  // Agent identifier (agent is resource)
  // "agent" claim omitted
  "sub": "user-12345",              // User identifier (SSO)
  "scope": "profile email",         // Authorized scopes (API access)
  "cnf": {
    "jwk": { ... }                   // Agent's signing key
  },
  "exp": 1730221200
}
```

**When agent accesses another resource (Phase 4):**
```json
{
  "iss": "https://auth.example",
  "aud": "https://resource.example", // Resource identifier
  "agent": "https://agent.example",  // Agent claim present
  "sub": "user-12345",
  "scope": "data.read",
  "cnf": {
    "jwk": { ... }
  },
  "exp": 1730221200
}
```

## Testing

### Automated Testing
```bash
python demo_phase5.py
```

This runs the complete flow with user simulator automatically.

### Manual Browser Testing

The demo script handles everything automatically:

```bash
python demo_phase5.py --manual
```

Copy the redirect URL and open it in your browser:

```
http://127.0.0.1:8003/agent/auth?request_token=...&redirect_uri=http://127.0.0.1:8001/callback
```

#### Authenticate and Grant Consent

1. **Login Page**: Enter credentials
   - Username: `testuser`
   - Password: `testpass`
   - Click "Login"

2. **Consent Page**: Review the authorization request
   - Shows Agent (same as Resource) and requested scopes
   - Click "Grant Access" to approve or "Deny" to reject

#### Agent Exchanges Code

After you grant consent, the browser redirects to:
```
http://127.0.0.1:8001/callback?code=...
```

The agent's `/callback` endpoint receives this and automatically exchanges the code for an auth token. The demo script then verifies the token claims.

### Unit Tests
```bash
pytest tests/test_phase5.py -v
```

## What Was Implemented

### Core Components

1. **Auth Server Enhancements** (`participants/auth_server.py`)
   - `_handle_token_request()`: Accepts `scope` or `auth_request_url` when `resource_token` is not provided
   - Validates that exactly one of `resource_token`, `scope`, or `auth_request_url` is provided
   - Uses agent identifier as resource identifier when `scope`/`auth_request_url` is provided
   - `_issue_auth_token()`: Added `agent_is_resource` parameter
     - When `agent_is_resource=True`: Sets `aud` = agent identifier, omits `agent` claim
     - When `agent_is_resource=False`: Sets `aud` = resource parameter, includes `agent` claim
   - `_generate_request_token()`: Stores `agent_is_resource` flag for code exchange
   - `_handle_code_exchange()`: Uses `agent_is_resource` from code details when issuing token

2. **Token Creation** (`core/tokens.py`)
   - `create_auth_token()`: Added `agent_is_resource` parameter
   - Conditionally omits `agent` claim when `agent_is_resource=True`
   - Sets `aud` appropriately based on `agent_is_resource` flag

3. **Agent Enhancements** (`participants/agent.py`)
   - `request_self_authorization()`: New method for requesting authorization directly with scope
     - Makes signed request to auth server with `scope` parameter (no `resource_token`)
     - Handles `request_token` response and completes user consent flow
     - Stores auth token for use in SSO and API access

4. **Demo Script** (`demo_phase5.py`)
   - Interactive demonstration of agent-is-resource flow
   - Supports automated mode (with user simulator) and manual mode (browser-based)
   - Verifies auth token claims:
     - `aud` = agent identifier
     - `agent` claim omitted
     - `sub` claim present
     - `scope` correct

5. **Tests** (`tests/test_phase5.py`)
   - Unit tests for direct authorization request
   - Unit tests for auth token claims validation
   - Integration test for complete flow

## Use Cases

### Single Sign-On (SSO)

An agent can authenticate users to itself using the auth server. The auth token contains the user identifier (`sub` claim) which the agent can use to verify user identity and provide SSO functionality.

### API Access by Delegates

Agent delegates can use the same auth token to call the agent's APIs. The token contains both user identity (`sub`) and authorization (`scope`), enabling fine-grained access control.

### Unified Token

Unlike OIDC where ID tokens and access tokens are separate, AAuth provides a single unified token that serves both authentication and authorization purposes. This eliminates confusion and prevents common mistakes like misusing ID tokens for API access.

## Differences from Phase 4

| Aspect | Phase 4 | Phase 5 |
|--------|---------|---------|
| **Request Parameter** | `resource_token` | `scope` or `auth_request_url` |
| **Resource** | Separate resource | Agent itself |
| **Token `aud`** | Resource identifier | Agent identifier |
| **Token `agent` claim** | Present | Omitted |
| **Use Case** | Agent accesses another resource | Agent authenticates users to itself |

## Implementation Notes

- **Backward compatibility**: Phase 4 flow (with `resource_token`) continues to work
- **Token format**: When `agent_is_resource=True`, the `agent` claim is omitted per SPEC.md Section 7.3
- **Policy evaluation**: Auth server allows agent to request authorization to itself (agent identifier = resource identifier)
- **User consent**: Same user consent flow as Phase 4, but token issued with different claims structure

## Output

```bash
❯ python demo_phase5.py --manual

================================================================================
Phase 5: Agent is Resource Demo
================================================================================

MODE: Manual Browser Testing
================================================================================
This demo shows the agent-is-resource SSO flow with manual browser interaction:
1. User visits agent's website (simulated)
2. Agent detects user needs authentication and initiates SSO flow
3. Agent requests self-authorization with scope (no resource_token)
4. Auth server returns request_token
5. **YOU WILL BE PROMPTED TO OPEN A URL IN YOUR BROWSER**
6. Authenticate and grant consent in the browser
7. Agent exchanges authorization code for auth token
8. Verify auth token claims (aud=agent, agent omitted, sub present)

Demo Credentials:
  Username: testuser
  Password: testpass

Debug output is enabled by default.
================================================================================

Starting Agent...
Starting Auth Server...
Waiting for servers to start...
INFO:     Started server process [95376]
INFO:     Waiting for application startup.
INFO:     Started server process [95376]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8003 (Press CTRL+C to quit)

================================================================================
Ready to start test (Manual Browser Testing mode).
Press Enter to begin...
================================================================================


================================================================================
TEST 1: Agent is Resource Flow (Manual Browser Testing)
================================================================================
Description: User visits agent's website, agent initiates SSO flow,
             user grants consent, agent receives auth token with
             aud=agent and agent claim omitted.
================================================================================

📱 User visits agent's website...
🔐 Agent detects user needs authentication
   → Initiating SSO flow with auth server...
📤 Agent requests self-authorization with scope: profile email
INFO:     127.0.0.1:58695 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8003/agent/token
================================================================================
POST http://127.0.0.1:8003/agent/token HTTP/1.1
Content-Digest: sha-256=:OFaZH+r0qhLPAY5XJbV5HgE303PsVku3XP6FuRZkNwU=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:ftk0sKV3cEj12lfImVjxr_ILcIAvOrxiIeIcNwsrFX3OUUNxkl0rUVAD3pu4onM9cdW3WLsM2cTj3mPvFQk3CQ:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")

[Body (81 bytes)]
request_type=auth&scope=profile email&redirect_uri=http://127.0.0.1:8001/callback
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:OFaZH+r0qhLPAY5XJbV5HgE303PsVku3XP6FuRZkNwU=:
content-length: 81
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:ftk0sKV3cEj12lfImVjxr_ILcIAvOrxiIeIcNwsrFX3OUUNxkl0rUVAD3pu4onM9cdW3WLsM2cTj3mPvFQk3CQ:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (81 bytes)]
request_type=auth&scope=profile email&redirect_uri=http://127.0.0.1:8001/callback
================================================================================

INFO:     127.0.0.1:58697 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58698 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58699 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58700 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "request_token": "OZgbWUWb9uxY4iNhLeVI0J18IUBVJjKqcBJj74Lqaxk",
  "expires_in": 600
}
================================================================================

INFO:     127.0.0.1:58696 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8003/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 80
content-type: application/json
date: Mon, 19 Jan 2026 01:28:56 GMT
server: uvicorn

[Body (80 bytes)]
{"request_token":"OZgbWUWb9uxY4iNhLeVI0J18IUBVJjKqcBJj74Lqaxk","expires_in":600}
================================================================================

INFO:     127.0.0.1:58701 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
MANUAL CONSENT REQUIRED
================================================================================

Please open the following URL in your browser:

  http://127.0.0.1:8003/agent/auth?request_token=OZgbWUWb9uxY4iNhLeVI0J18IUBVJjKqcBJj74Lqaxk&redirect_uri=http://127.0.0.1:8001/callback

After granting consent, the agent will automatically exchange the code.
Waiting for authorization code...
================================================================================

INFO:     127.0.0.1:58702 - "GET /agent/auth?request_token=OZgbWUWb9uxY4iNhLeVI0J18IUBVJjKqcBJj74Lqaxk&redirect_uri=http://127.0.0.1:8001/callback HTTP/1.1" 200 OK
INFO:     127.0.0.1:58703 - "POST /agent/auth HTTP/1.1" 303 See Other
INFO:     127.0.0.1:58703 - "GET /agent/auth?request_token=OZgbWUWb9uxY4iNhLeVI0J18IUBVJjKqcBJj74Lqaxk&redirect_uri=http://127.0.0.1:8001/callback HTTP/1.1" 200 OK
INFO:     127.0.0.1:58703 - "POST /agent/auth HTTP/1.1" 303 See Other
INFO:     127.0.0.1:58705 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:mNU1Qvm5izl/9WVrkj25Rl/JxRGH8FuhVWGzzEQcnDQ=:
content-length: 110
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:VEVaNt2_PMqekRx9NP7fzU3JPVmg5qAA93oHv8yEqMXyHu-BlsSm98REdLgD0u5qNeFPz27_l6P_0zLOrufiAA:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (110 bytes)]
request_type=code&code=18q-JYO8dsGoFkyp-hp-T1AUUe3RQO60aUi7NqiqZ3w&redirect_uri=http://127.0.0.1:8001/callback
================================================================================

INFO:     127.0.0.1:58707 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58708 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58709 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58710 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDEiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicElKZ0d0RHNVTHR3djRMUjRlbzFsX0szUTl0elhUT185emR3S2l2Y1VoUSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJleHAiOjE3Njg3ODk3NTcsInN1YiI6InRlc3R1c2VyIn0.25e6kFS0a5rhcNZswVj111oN9toI2zULgwWqOl2fb6HdxnGlryFmk5864hqkrMZPhTeePWkhTSNB_E_uREa9AQ",
  "expires_in": 3600,
  "token_type": "Bearer"
}
================================================================================

INFO:     127.0.0.1:58706 - "POST /agent/token HTTP/1.1" 200 OK
INFO:     127.0.0.1:58704 - "GET /callback?code=18q-JYO8dsGoFkyp-hp-T1AUUe3RQO60aUi7NqiqZ3w HTTP/1.1" 200 OK

✓ Auth token obtained: eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4...

Verifying auth token claims:
  Token payload: {
  "iss": "http://127.0.0.1:8003",
  "aud": "http://127.0.0.1:8001",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "pIJgGtDsULtwv4LR4eo1l_K3Q9tzXTO_9zdwKivcUhQ",
      "kid": "key-1"
    }
  },
  "scope": "profile email",
  "exp": 1768789757,
  "sub": "testuser"
}
  ✓ aud claim correct: http://127.0.0.1:8001
  ✓ agent claim correctly omitted
  ✓ sub claim present: testuser
  ✓ scope correct: profile email

✓ TEST 1 PASSED: All token claims validated correctly
  - aud = agent identifier: ✓
  - agent claim omitted: ✓
  - sub (user identifier) present: ✓
  - scope correct: ✓

================================================================================
TEST SUMMARY
================================================================================
✓ PASSED: TEST 1: Agent is Resource Flow

--------------------------------------------------------------------------------
Total: 1 | Passed: 1 | Failed: 0
================================================================================


================================================================================
MANUAL TESTING INSTRUCTIONS
================================================================================
To test manually:
1. The agent will request self-authorization
2. Open the authorization URL in your browser
3. Login with: testuser / testpass
4. Grant consent
5. The agent will automatically exchange the code for tokens
================================================================================

Servers are still running. Press Ctrl+C to stop.
```