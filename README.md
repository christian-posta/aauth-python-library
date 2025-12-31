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
- [CLAUDE-CHAT.md](CLAUDE-CHAT.md) - Design discussions and Q&A

## Implementation Status

- [x] Phase 1: Pseudonymous flow (sig=hwk)
- [ ] Phase 2: Agent identity (sig=jwks)
- [ ] Phase 3: Autonomous authorization (tokens)
- [ ] Phase 4: User delegation (OAuth-like flow)
