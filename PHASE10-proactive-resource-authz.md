# Phase 10: Proactive Resource Authorization

Phase 10 demonstrates **Proactive Resource Authorization** using the resource's authorization endpoint (`POST /authorize`) with the `AAuth-Mission` header. This enables agents to obtain resource tokens proactively before accessing the resource.

## Overview

In the standard reactive flow, agents receive resource tokens from `401` challenges. In the proactive flow:

1. Agent proposes a mission to its Mission Manager
2. Mission Manager approves the mission and returns mission text + hash
3. Agent proactively requests a resource token from the resource's `authorization_endpoint`
4. Agent includes the `AAuth-Mission` header with the mission hash
5. Resource issues a resource token containing the mission claim
6. Agent sends the resource token to the Mission Manager's `token_endpoint`
7. Mission Manager federates with the resource's Auth Server
8. Agent receives an auth token with the mission claim
9. Agent accesses the resource with the auth token

## Architecture Flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant MM as Mission Manager
    participant R as Resource
    participant AS as Auth Server

    Note over A,MM: Step 1: Mission Proposal
    A->>MM: POST /mission (mission proposal)
    MM->>MM: Evaluate & approve
    MM->>A: 200 OK (mission text, s256 hash)

    Note over A,R: Step 2: Proactive Authorization
    A->>R: POST /authorize<br/>AAuth-Mission: approver=...; s256=...<br/>(sig=jwt + agent token; aauth-mission signed)
    R->>R: Verify signature<br/>Validate mission
    R->>A: 200 OK (resource_token with mission)

    Note over A,MM: Step 3: Auth Token Request
    A->>MM: POST /token<br/>resource_token (+ agent_token via sig=jwt)
    MM->>AS: POST /token (federation)
    AS->>MM: auth_token with mission
    MM->>A: 200 OK (auth_token)

    Note over A,R: Step 4: Resource Access
    A->>R: GET /data (scheme=jwt with auth_token)
    R->>R: Verify auth token<br/>Check mission.s256
    R->>A: 200 OK
```

## Key Features

### Mission Flow

- **Mission Proposal**: Agent proposes mission to MM
- **Mission Approval**: MM evaluates and approves (auto-approved in demo)
- **Mission Hash**: SHA-256 hash (`s256`) of mission text
- **Mission Propagation**: Mission hash flows through token chain

### Proactive Authorization Endpoint

- **Endpoint**: `POST /authorize` on resource
- **Header**: `AAuth-Mission: approver=...; s256=...` (included in the HTTP message signature as `aauth-mission`)
- **Authentication**: HTTP Message Signature with `sig=jwt` and the agent token in `Signature-Key` (per SPEC.md §Authorization Endpoint Request)
- **Response**: Resource token with mission claim

### Token Chain

All tokens in the chain include the mission claim:

1. **Resource Token**: `mission.s256` from `AAuth-Mission` header
2. **Auth Token**: `mission.s256` propagated from resource token
3. **Resource Validation**: Verifies mission hash in auth token

## What Was Implemented

### Core Components

- **`participants/mission_manager.py`**
  - `POST /mission` endpoint for mission proposals
  - Mission approval logic
  - Mission storage and hash generation

- **`participants/resource.py`**
  - `POST /authorize` endpoint for proactive authorization
  - `AAuth-Mission` header parsing
  - Resource token issuance with mission claim

- **`participants/agent.py`**
  - Mission proposal helper methods
  - Proactive authorization flow
  - Mission hash handling

### Demo Script

- **`demo_phase10.py`**
  - End-to-end proactive authorization flow
  - Mission proposal and approval
  - Resource token acquisition with mission
  - Auth token acquisition and resource access

## Testing

```bash
python demo_phase10.py
pytest tests/test_phase10.py -v
```

## Spec References

- **Authorization endpoint request**: SPEC.md §Authorization Endpoint Request (including `AAuth-Mission` in signed components)
- **Resource token issuance / structure**: SPEC.md §Resource Token Structure
- **Missions / `AAuth-Mission`**: SPEC.md §Mission and §AAuth-Mission Request Header
- **PS token endpoint / PS→AS federation**: SPEC.md §PS Token Endpoint and §PS-to-AS Token Request

## Notes

- Proactive authorization is optional; reactive flow (401 challenge) still works
- Mission hash (`s256`) must match across the entire token chain
- Resources validate missions by checking the hash in auth tokens
- Mission Manager auto-approves in demo; production would require approval logic
