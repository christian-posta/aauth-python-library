---
name: AAuth Python Implementation
overview: Implement AAuth protocol in Python with FastAPI, covering all phases (pseudonymous, identity, autonomous, user delegation) without agent delegation complexity. The agent acts as an agent server using sig=jwks directly.
todos:
  - id: setup
    content: Set up project structure, create requirements.txt, initialize FastAPI apps for each participant
    status: pending
  - id: phase1-core
    content: Implement core/httpsig.py and core/crypto_utils.py for HTTP Message Signing and Ed25519 key generation
    status: pending
    dependencies:
      - setup
  - id: phase1-participants
    content: Implement basic agent.py and resource.py for Phase 1 (pseudonymous flow with sig=hwk)
    status: pending
    dependencies:
      - phase1-core
  - id: phase1-tests
    content: Write tests for Phase 1 pseudonymous flow
    status: pending
    dependencies:
      - phase1-participants
  - id: phase2-metadata
    content: Implement core/metadata.py for metadata document generation and parsing
    status: pending
    dependencies:
      - phase1-tests
  - id: phase2-jwks
    content: Add JWKS endpoints and identity verification to agent.py and resource.py (Phase 2)
    status: pending
    dependencies:
      - phase2-metadata
  - id: phase2-tests
    content: Write tests for Phase 2 identity verification flow
    status: pending
    dependencies:
      - phase2-jwks
  - id: phase3-tokens
    content: Implement core/tokens.py for resource token and auth token generation/validation
    status: pending
    dependencies:
      - phase2-tests
  - id: phase3-auth-server
    content: Implement participants/auth_server.py with policy evaluation and token issuance
    status: pending
    dependencies:
      - phase3-tokens
  - id: phase3-flow
    content: Implement flows/autonomous.py for Phase 3 autonomous authorization flow
    status: pending
    dependencies:
      - phase3-auth-server
  - id: phase3-tests
    content: Write tests for Phase 3 autonomous flow end-to-end
    status: pending
    dependencies:
      - phase3-flow
  - id: phase4-user-sim
    content: Implement participants/user_simulator.py for browser redirect simulation
    status: pending
    dependencies:
      - phase3-tests
  - id: phase4-auth-endpoints
    content: Add request_token and authorization code exchange endpoints to auth_server.py
    status: pending
    dependencies:
      - phase4-user-sim
  - id: phase4-flow
    content: Implement flows/user_delegated.py for Phase 4 user delegation flow
    status: pending
    dependencies:
      - phase4-auth-endpoints
  - id: phase4-tests
    content: Write tests for Phase 4 user delegation flow end-to-end
    status: pending
    dependencies:
      - phase4-flow
  - id: integration
    content: Create main.py orchestrator to run all participants together and verify full flows
    status: pending
    dependencies:
      - phase4-tests
---

# AAuth Protocol Implementation Plan

## Overview

Implement AAuth protocol in Python to understand the protocol through hands-on coding. The implementation will cover all four phases incrementally, starting with pseudonymous access and building up to full user delegation flows. The agent will act as an agent server (no delegation) using `sig=jwks` for simplicity.

## Architecture

The implementation follows a modular structure with core utilities, participant implementations, and flow orchestrators:

```
aauth/
├── core/
│   ├── httpsig.py          # HTTP Message Signing (RFC 9421)
│   ├── tokens.py           # JWT generation/validation (3 token types)
│   ├── metadata.py         # Metadata document handling
│   └── crypto_utils.py     # Key generation, JWKS handling
├── participants/
│   ├── agent.py            # Agent server (uses sig=jwks)
│   ├── resource.py         # Resource server
│   ├── auth_server.py       # Authorization server
│   └── user_simulator.py    # Simulates browser redirects
├── flows/
│   ├── autonomous.py       # Machine-to-machine flow (Phase 3)
│   └── user_delegated.py   # User consent flow (Phase 4)
├── tests/
│   ├── test_httpsig.py
│   ├── test_tokens.py
│   ├── test_flows.py
│   └── integration/
└── main.py                 # Orchestrator to run all participants
```

## Implementation Phases

### Phase 1: Pseudonymous Access
**Goal**: Basic proof-of-possession without identity

- Agent generates ephemeral Ed25519 key pair
- Agent signs request with `sig=hwk` (public key in header)
- Resource validates signature
- No tokens, no identity - just signature verification

**Deliverables**:
- `core/httpsig.py`: HTTP Message Signing implementation
- `core/crypto_utils.py`: Ed25519 key generation
- `participants/agent.py`: Basic agent that signs requests
- `participants/resource.py`: Basic resource that validates signatures

### Phase 2: Agent Identity
**Goal**: Agent identity verification via JWKS

- Agent publishes JWKS at `/.well-known/aauth-agent-server`
- Agent signs with `sig=jwks` (references own JWKS)
- Resource fetches JWKS and validates identity
- Still no tokens - just identity verification

**Deliverables**:
- `core/metadata.py`: Metadata document generation/parsing
- `participants/agent.py`: Add JWKS endpoint and metadata
- `participants/resource.py`: Add JWKS fetching and validation

### Phase 3: Autonomous Authorization
**Goal**: Full token flow without user interaction

- Resource issues resource token (resource+jwt)
- Agent presents resource token to auth server
- Auth server evaluates policy (no user interaction)
- Auth server issues auth token (auth+jwt) + refresh token
- Agent uses auth token to access resource

**Deliverables**:
- `core/tokens.py`: JWT generation/validation for all 3 token types
- `participants/resource.py`: Resource token issuance
- `participants/auth_server.py`: Auth server with policy evaluation
- `flows/autonomous.py`: Autonomous flow orchestrator

### Phase 4: User Delegation
**Goal**: Full OAuth-like authorization code flow

- Auth server returns `request_token` when user consent needed
- Simulate browser redirect flow
- User authenticates and consents
- Authorization code exchange
- Auth token includes user identity (`sub`, `email`)

**Deliverables**:
- `participants/auth_server.py`: Add request_token and code exchange
- `participants/user_simulator.py`: Browser redirect simulation
- `flows/user_delegated.py`: User delegation flow orchestrator

## Core Components

### 1. HTTP Message Signing (`core/httpsig.py`)

**Dependencies**: `http-message-signatures` library (RFC 9421)

**Key Functions**:
- `sign_request(request, private_key, sig_scheme, **kwargs)` - Sign HTTP request
- `verify_signature(request, public_key)` - Verify HTTP signature
- `parse_signature_key(header_value)` - Parse Signature-Key header
- Support for `sig=hwk`, `sig=jwks`, `sig=jwt` schemes

**Signature-Key Header Formats**:
- `sig=hwk; kty="OKP"; crv="Ed25519"; x="..."`
- `sig=jwks; id="https://agent.example"; kid="key-1"`
- `sig=jwt; jwt="eyJhbGc..."`

### 2. Token Handling (`core/tokens.py`)

**Dependencies**: `PyJWT`, `jwcrypto` (for JWK support)

**Token Types**:
1. **Agent Token** (`typ: agent+jwt`) - Not needed for this implementation (no delegation)
2. **Resource Token** (`typ: resource+jwt`) - Issued by resource
3. **Auth Token** (`typ: auth+jwt`) - Issued by auth server

**Key Functions**:
- `create_resource_token(iss, aud, agent, agent_jkt, scope, private_key)` - Issue resource token
- `create_auth_token(iss, agent, aud, cnf_jwk, scope, sub, private_key)` - Issue auth token
- `verify_token(token, jwks_uri)` - Verify token signature and claims
- `calculate_jwk_thumbprint(jwk)` - RFC 7638 thumbprint for agent_jkt claim

**Token Claims**:
- Resource token: `iss`, `aud`, `agent`, `agent_jkt`, `scope`, `exp`
- Auth token: `iss`, `agent`, `aud`, `cnf.jwk`, `scope`, `sub` (optional), `exp`

### 3. Metadata (`core/metadata.py`)

**Endpoints**:
- `/.well-known/aauth-agent-server` - Agent metadata
- `/.well-known/aauth-resource-server` - Resource metadata
- `/.well-known/aauth-auth-server` - Auth server metadata

**Key Functions**:
- `generate_agent_metadata(agent_id, jwks_uri)` - Generate agent metadata
- `generate_resource_metadata(resource_id, jwks_uri)` - Generate resource metadata
- `generate_auth_metadata(auth_id, jwks_uri, token_endpoint)` - Generate auth metadata
- `fetch_metadata(url)` - Fetch and parse metadata

### 4. Crypto Utilities (`core/crypto_utils.py`)

**Dependencies**: `cryptography` library

**Key Functions**:
- `generate_ed25519_keypair()` - Generate Ed25519 key pair
- `private_key_to_jwk(private_key, kid)` - Convert to JWK format
- `public_key_to_jwk(public_key, kid)` - Convert to JWK format
- `generate_jwks(keys)` - Generate JWKS document
- `load_key_from_file(path)` - Load key from file (for persistence)

## Participants

### Agent (`participants/agent.py`)

**FastAPI Application** with endpoints:
- `GET /.well-known/aauth-agent-server` - Metadata endpoint
- `GET /jwks.json` - JWKS endpoint
- `POST /callback` - OAuth callback handler (Phase 4)

**Key Methods**:
- `sign_request(url, method, headers, body)` - Sign outgoing requests
- `request_resource(resource_url, scope)` - Request access to resource
- `exchange_code(auth_code)` - Exchange authorization code (Phase 4)

**State**:
- Agent ID (HTTPS URL)
- Ed25519 private/public key pair
- Current auth token (if obtained)
- Refresh token (if obtained)

### Resource (`participants/resource.py`)

**FastAPI Application** with endpoints:
- `GET /.well-known/aauth-resource-server` - Metadata endpoint
- `GET /jwks.json` - JWKS endpoint
- `GET /data` - Protected resource endpoint
- `POST /data` - Protected resource endpoint

**Key Methods**:
- `verify_request(request)` - Verify HTTPSig signature
- `issue_resource_token(agent, agent_jkt, scope)` - Issue resource token
- `verify_auth_token(token)` - Verify auth token and extract claims

**Challenge Flow**:
- On unauthorized request: Return 401 with `WWW-Authenticate: AAuth resource_token=...`

### Auth Server (`participants/auth_server.py`)

**FastAPI Application** with endpoints:
- `GET /.well-known/aauth-auth-server` - Metadata endpoint
- `GET /jwks.json` - JWKS endpoint
- `POST /agent/token` - Token endpoint (autonomous + code exchange)
- `GET /agent/auth` - Authorization endpoint (user consent)
- `POST /agent/auth` - Consent submission

**Key Methods**:
- `evaluate_policy(agent, resource, scope)` - Policy evaluation (autonomous)
- `issue_auth_token(agent, resource, scope, cnf_jwk, sub)` - Issue auth token
- `issue_refresh_token(agent, sub, cnf_jwk)` - Issue refresh token
- `exchange_code(code, agent)` - Exchange authorization code

**State Management** (in-memory dicts):
- `pending_requests` - request_token → request details
- `authorization_codes` - code → authorization details
- `refresh_tokens` - refresh_token → token binding

### User Simulator (`participants/user_simulator.py`)

**Simulates browser redirect flow**:

**Key Methods**:
- `follow_redirect(location)` - Follow redirect URL
- `authenticate(username, password)` - Simulate user login
- `consent(scope)` - Simulate user consent
- `complete_flow(request_token_url, redirect_uri)` - Complete full redirect flow

## Flow Implementations

### Autonomous Flow (`flows/autonomous.py`)

**Sequence**:
1. Agent → Resource: GET /data (unsigned)
2. Resource → Agent: 401 + resource_token
3. Agent → Auth Server: POST /agent/token (resource_token, sig=jwks)
4. Auth Server → Agent: 200 + auth_token + refresh_token
5. Agent → Resource: GET /data (auth_token, sig=jwt)
6. Resource → Agent: 200 + data

### User Delegated Flow (`flows/user_delegated.py`)

**Sequence**:
1. Agent → Resource: GET /data (unsigned)
2. Resource → Agent: 401 + resource_token
3. Agent → Auth Server: POST /agent/token (resource_token, sig=jwks)
4. Auth Server → Agent: 200 + request_token
5. Agent → User Simulator: Redirect to auth server
6. User Simulator → Auth Server: GET /agent/auth?request_token=...
7. Auth Server → User Simulator: Login/consent page
8. User Simulator → Auth Server: POST /agent/auth (credentials + consent)
9. Auth Server → User Simulator: Redirect to agent with code
10. User Simulator → Agent: GET /callback?code=...
11. Agent → Auth Server: POST /agent/token (code, sig=jwks)
12. Auth Server → Agent: 200 + auth_token + refresh_token
13. Agent → Resource: GET /data (auth_token, sig=jwt)
14. Resource → Agent: 200 + data

## Dependencies

**requirements.txt**:
```
fastapi>=0.104.0
uvicorn>=0.24.0
httpx>=0.25.0
http-message-signatures>=1.0.0
http-sfv>=0.9.8
cryptography>=41.0.0
PyJWT>=2.8.0
jwcrypto>=1.5.0
pydantic>=2.0.0
python-dateutil>=2.8.0
```

## Testing Strategy

### Unit Tests
- `test_httpsig.py`: Test HTTP signing/verification with known test vectors
- `test_tokens.py`: Test JWT generation/validation for each token type
- `test_metadata.py`: Test metadata generation/parsing
- `test_crypto_utils.py`: Test key generation and JWKS handling

### Integration Tests
- `test_phase1.py`: Pseudonymous flow end-to-end
- `test_phase2.py`: Identity verification flow
- `test_phase3.py`: Autonomous authorization flow
- `test_phase4.py`: User delegation flow

**Test Approach**:
- Use deterministic keys (no randomness) for reproducible tests
- Mock HTTP requests where appropriate
- Test each phase independently before moving to next

## Implementation Order

1. **Setup**: Project structure, dependencies, basic FastAPI apps
2. **Phase 1**: HTTPSig + pseudonymous flow
3. **Phase 2**: Metadata + JWKS + identity verification
4. **Phase 3**: Token machinery + autonomous flow
5. **Phase 4**: User delegation + redirect simulation

## Key Design Decisions

1. **No Agent Delegation**: Agent acts as agent server, uses `sig=jwks` directly
2. **In-Memory State**: Auth server uses dicts for simplicity (can be replaced with DB later)
3. **Ephemeral Keys**: Generate keys at startup (can add persistence later)
4. **Simulated Browser**: User simulator handles redirects programmatically
5. **Ed25519 Only**: Start with Ed25519 to keep crypto simple

## Success Criteria

- Phase 1: Agent can sign requests, resource validates signatures
- Phase 2: Resource can verify agent identity via JWKS
- Phase 3: Full autonomous token flow works end-to-end
- Phase 4: User delegation flow with redirects works end-to-end
- All phases have passing tests
- Code is well-structured and documented