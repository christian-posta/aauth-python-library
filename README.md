# AAuth Protocol Implementation

A Python implementation of the AAuth protocol for learning and understanding the protocol through hands-on coding.

## Overview

This project implements the AAuth protocol incrementally, phase by phase:
- **Phase 1**: Pseudonymous flow (proof-of-possession without identity)
- **Phase 2**: Agent identity (JWKS-based identity verification)
- **Phase 3**: Autonomous authorization (full token flow)
- **Phase 4**: User delegation (OAuth-like authorization code flow)

## Quick Start

See [INSTRUCTIONS.md](INSTRUCTIONS.md) for setup and usage instructions.

## Project Structure

```
aauth/
├── core/              # Core utilities (HTTPSig, tokens, crypto)
├── participants/      # Protocol participants (agent, resource, auth_server)
├── flows/            # Flow implementations
└── tests/            # Test suite
```

## Documentation

- [INSTRUCTIONS.md](INSTRUCTIONS.md) - Setup and usage instructions
- [PHASE1.md](PHASE1.md) - Phase 1 implementation details
- [PHASE2.md](PHASE2.md) - Phase 2 implementation details
- [PLAN.md](PLAN.md) - Overall implementation plan


## Implementation Status

- [x] Phase 1: Pseudonymous flow (sig=hwk) - Complete
- [x] Phase 2: Agent identity (sig=jwks) - Complete
- [ ] Phase 3: Autonomous authorization (tokens) - Planned
- [ ] Phase 4: User delegation (OAuth-like flow) - Planned
