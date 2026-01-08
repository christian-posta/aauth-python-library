# AAuth Protocol Implementation

A Python implementation of the AAuth protocol for learning and understanding the protocol through hands-on coding.

## Overview

This project implements the AAuth protocol incrementally, phase by phase:
- **Phase 1**: Pseudonymous flow (proof-of-possession without identity)
- **Phase 2**: Agent identity (JWKS-based identity verification)
- **Phase 3**: Autonomous authorization (full token flow)
- **Phase 4**: User delegation (OAuth-like authorization code flow)
- **Phase 5**: Agent is Resource (SSO and unified token flow)

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

Demonstrates OAuth-like authorization code flow with user consent:

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
```

## Phase Overview

### Phase 1: Pseudonymous Flow
- Agent signs requests with `sig=hwk` (public key in header)
- Resource validates signatures
- No tokens, no identity - just signature verification

See [PHASE1.md](PHASE1.md) for detailed documentation.

### Phase 2: Agent Identity via JWKS
- Agent publishes metadata at `/.well-known/aauth-agent`
- Agent publishes JWKS at `/jwks.json`
- Resource can verify agent identity using `sig=jwks` scheme
- Separate endpoints (`/data-hwk`, `/data-jwks`) for both schemes

See [PHASE2.md](PHASE2.md) for detailed documentation.

### Phase 3: Autonomous Authorization
- Resources issue resource tokens when agents request access
- Agents present resource tokens to auth servers
- Auth servers validate resource tokens and issue auth tokens
- Agents use auth tokens to access protected resources
- Complete token flow without user interaction

See [PHASE3.md](PHASE3.md) for detailed documentation.

### Phase 4: User Delegation
- Auth servers issue `request_token` when user consent is required
- Agents redirect users to auth server's authorization endpoint
- Users authenticate and grant consent
- Auth server redirects back with authorization code
- Agents exchange code for auth tokens with `sub` claim

See [PHASE4.md](PHASE4.md) for detailed documentation.

### Phase 5: Agent is Resource
- Agent requests authorization directly with `scope` (no `resource_token`)
- Agent identifier matches resource identifier (agent authenticates users to itself)
- Auth token has `aud` = agent identifier and `agent` claim omitted
- Unified token serves both SSO (user identity) and API access purposes
- Solves OIDC limitation where ID tokens and access tokens are separate

See [PHASE5.md](PHASE5.md) for detailed documentation.

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

## Project Structure

```
aauth/
├── core/              # Core utilities (HTTPSig, tokens, crypto)
├── participants/      # Protocol participants (agent, resource, auth_server)
├── flows/            # Flow implementations
└── tests/            # Test suite
```

## Documentation

- [PHASE1.md](PHASE1.md) - Phase 1 implementation details
- [PHASE2.md](PHASE2.md) - Phase 2 implementation details
- [PHASE3.md](PHASE3.md) - Phase 3 implementation details
- [PHASE4.md](PHASE4.md) - Phase 4 implementation details
- [PHASE5.md](PHASE5.md) - Phase 5 implementation details
- [SPEC.md](SPEC.md) - AAuth protocol specification
- [PLAN.md](PLAN.md) - Overall implementation plan


