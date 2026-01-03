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

