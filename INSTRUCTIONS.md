# AAuth Implementation Instructions

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run tests:
```bash
pytest tests/test_phase1.py -v
```

## Running Participants

### Run Resource Server:
```bash
python -m participants.resource
```

### Run Agent:
```bash
python -m participants.agent
```

## Running Phase 1 Demo

To see Phase 1 in action:
```bash
python demo_phase1.py
```

This will:
- Start the resource server
- Make an unsigned request (should fail)
- Make a signed request (should succeed)
- Test POST request with body

## Testing

Run all Phase 1 tests:
```bash
pytest tests/test_phase1.py -v
```

Run specific test:
```bash
pytest tests/test_phase1.py::test_phase1_pseudonymous_flow -v
```

## Phase 1: Pseudonymous Flow

Phase 1 implements basic proof-of-possession without identity:
- Agent signs requests with `sig=hwk` (public key in header)
- Resource validates signatures
- No tokens, no identity - just signature verification

See [PHASE1.md](PHASE1.md) for detailed Phase 1 documentation.

## Phase 2: Agent Identity via JWKS

Phase 2 adds agent identity verification:
- Agent publishes metadata at `/.well-known/aauth-agent`
- Agent publishes JWKS at `/jwks.json`
- Resource can verify agent identity using `sig=jwks` scheme
- Separate endpoints (`/data-hwk`, `/data-jwks`) for both schemes

See [PHASE2.md](PHASE2.md) for detailed Phase 2 documentation.

### Running Phase 2 Demo

```bash
python demo_phase2.py
```

### Running Phase 2 Tests

```bash
pytest tests/test_phase2.py -v
```

## Project Structure

```
aauth/
├── core/              # Core utilities (HTTPSig, tokens, crypto)
├── participants/      # Protocol participants (agent, resource, auth_server)
├── flows/            # Flow implementations
└── tests/            # Test suite
```

## Implementation Status

- [x] Phase 1: Pseudonymous flow (sig=hwk) - Complete
- [x] Phase 2: Agent identity (sig=jwks) - Complete
- [ ] Phase 3: Autonomous authorization (tokens) - Planned
- [ ] Phase 4: User delegation (OAuth-like flow) - Planned

