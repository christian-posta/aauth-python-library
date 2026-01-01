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

## Phase 3: Autonomous Authorization

Phase 3 implements autonomous authorization flow:
- Resources issue resource tokens when agents request access
- Agents present resource tokens to auth servers
- Auth servers validate resource tokens and issue auth tokens
- Agents use auth tokens to access protected resources
- Complete token flow without user interaction

See [PHASE3.md](PHASE3.md) for detailed Phase 3 documentation.

### Running Phase 3 Demo

```bash
python demo_phase3.py
```

This will start all three participants (agent, resource, auth server) and demonstrate the complete autonomous authorization flow.

### Running Phase 3 Tests

```bash
pytest tests/test_phase3.py -v
```

### Manual Testing Phase 3

**Terminal 1 - Agent**:
```bash
python -c "from participants.agent import Agent; Agent('http://127.0.0.1:8001', port=8001).run()"
```

**Terminal 2 - Resource**:
```bash
python -c "from participants.resource import Resource; Resource('http://127.0.0.1:8002', port=8002, auth_server='http://127.0.0.1:8003').run()"
```

**Terminal 3 - Auth Server**:
```bash
python -c "from participants.auth_server import AuthServer; AuthServer('http://127.0.0.1:8003', port=8003).run()"
```

**Terminal 4 - Test**:
```python
import asyncio
from participants.agent import Agent

async def test():
    agent = Agent("http://127.0.0.1:8001", port=8001)
    response = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-auth",
        method="GET",
        sig_scheme="jwks"
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {response.json()}")

asyncio.run(test())
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
- [x] Phase 3: Autonomous authorization (tokens) - Complete
- [ ] Phase 4: User delegation (OAuth-like flow) - Planned

