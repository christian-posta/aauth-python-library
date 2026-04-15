# Phase 12: Mission Lifecycle

Phase 12 demonstrates the **complete mission lifecycle** from proposal through approval, token acquisition, and resource access. This phase shows how mission hashes (`s256`) are preserved across the entire token chain, per **SPEC.md** (Mission, Mission Approval, AAuth-Mission Request Header, PS token endpoint, PS–AS federation).

## Overview

The complete mission lifecycle includes:

1. **Discovery**: Agent discovers Person Server (PS) metadata to locate `mission_endpoint` and `token_endpoint`
2. **Proposal**: Agent proposes a mission to the PS (`POST` `mission_endpoint`)
3. **Approval**: PS approves and returns the **mission blob** in the response body and `approver` / `s256` in the **`AAuth-Mission` response header**
4. **Resource token**: Agent proactively obtains a resource token with mission context (`POST` `authorization_endpoint`, `AAuth-Mission` request header)
5. **Auth token**: Agent sends the resource token to the PS **`token_endpoint`**; in four-party mode the PS federates to the resource’s AS
6. **Resource access**: Agent accesses a protected resource using the auth token (`scheme=jwt`)
7. **Hash verification**: `s256` is checked against the approved mission and carried through tokens to access

## Architecture Flow

Aligned with SPEC.md: Person Server metadata (`#ps-metadata`), mission creation/approval (`#missions`), authorization endpoint with mission (`#fig-mission-context`), PS token endpoint (`#ps-token-endpoint`), PS–AS federation (`#ps-as-federation`).

```mermaid
sequenceDiagram
    participant A as Agent
    participant PS as Person Server
    participant R as Resource
    participant AS as Auth Server

    Note over A,PS: Step 1: Discovery
    A->>PS: GET /.well-known/aauth-person.json
    PS->>A: metadata (mission_endpoint, token_endpoint, …)

    Note over A,PS: Step 2: Mission proposal and approval
    A->>PS: POST /mission (HTTPSig, Signature-Key scheme=jwt)<br/>body: {"description", "tools"?}
    PS->>PS: review / approve (demo: auto-approve)
    PS->>A: 200 OK + mission blob body<br/>AAuth-Mission: approver=…; s256=…

    Note over A,R: Step 3: Proactive resource authorization
    A->>R: POST /authorize<br/>AAuth-Mission: approver=…; s256=…<br/>HTTPSig scheme=jwt (agent token; aauth-mission signed)
    R->>R: verify signature; embed mission in resource token
    R->>A: 200 OK + resource_token (mission.approver, mission.s256)

    Note over A,PS: Step 4: Auth token via PS (four-party)
    A->>PS: POST /token (HTTPSig, scheme=jwt)<br/>body: {"resource_token"}
    PS->>PS: evaluate mission context / log; if aud=AS, federate
    PS->>AS: POST /token (PS-signed; federation)
    AS->>PS: auth_token (mission claim preserved)
    PS->>A: 200 OK + auth_token

    Note over A,R: Step 5: Resource access
    A->>R: GET /data-auth (HTTPSig scheme=jwt, auth token)
    R->>R: verify aa-auth+jwt; mission.s256 in token
    R->>A: 200 OK (access granted)
```

## Key Features

### Mission lifecycle stages

1. **Discovery**: `GET /.well-known/aauth-person.json` (PS metadata; not `aauth-mission.json`).
   - `mission_endpoint`: mission proposal URL
   - `token_endpoint`: where the agent sends `resource_token` requests

2. **Proposal**: `POST` `{mission_endpoint}` — signed request per **Mission Creation** (`#missions`).
   - Body: `description` (Markdown) and optional `tools` (not `purpose` / `scope` / `resource_id` as the wire format).

3. **Approval** — **Mission Approval** (`#mission-approval`):
   - Response **body**: JSON **mission blob** (MUST include `approver`, `agent`, `approved_at`, `description`; MAY include `approved_tools`, `capabilities`).
   - Response **header**: `AAuth-Mission` with `approver` and `s256` (base64url SHA-256 of the **exact response body bytes**).

4. **Resource token**: `POST` `authorization_endpoint` (e.g. `/authorize`) with **`AAuth-Mission` request header**.
   - Per spec figures: HTTPSig with **scheme=jwt** (agent token); include `aauth-mission` in signed components when in a mission context.
   - Resource token payload includes `mission: { approver, s256 }` when mission-aware.

5. **Auth token**: `POST` PS **`token_endpoint`** with `resource_token` — **Agent Token Request** (`#ps-token-endpoint`): agent uses **scheme=jwt**. The PS evaluates the request against mission context and mission log; if `aud` on the resource token is the AS, the PS **federates** to the AS (`#ps-as-federation`) — agents do not call the AS `token_endpoint` directly in the normative four-party flow.

6. **Resource access**: Protected route (this demo: `GET /data-auth`) with **scheme=jwt** and the auth token; resource verifies the JWT and governance/mission claims as implemented.

### Mission hash verification

- **PS**: Computes `s256` from the approved mission blob octets returned as the `POST /mission` body; stores mission state keyed by `s256`.
- **Resource**: Copies `approver` / `s256` from the `AAuth-Mission` **request** header into the resource token `mission` claim.
- **AS**: Preserves `mission` in the auth token when issuing from a mission-bearing resource token.
- **Resource (access)**: Validates the auth token; mission integrity is the same `s256` chain end-to-end.

## Token chain

Per SPEC.md, `s256` is the base64url SHA-256 of the **approved mission JSON (response body bytes)** — not a separate “mission text” field:

```
POST /mission response body bytes (mission blob)
    ↓ SHA-256 → base64url
s256 (also in AAuth-Mission response header)
    ↓ (AAuth-Mission request header on POST /authorize)
Resource token { mission: { approver, s256 } }
    ↓ (POST /token at PS; PS may federate to AS)
Auth token { mission: { approver, s256 } }
    ↓ (scheme=jwt on resource request)
Resource verifies auth token and mission claim
```

## What was implemented

### Core components

- **`participants/mission_manager.py`** (`PersonServer`; alias `MissionManager`)
  - Metadata: `GET /.well-known/aauth-person.json` (`#ps-metadata`)
  - `POST /mission` — mission proposal verification, mission blob + `AAuth-Mission` response header
  - `POST /token` — broker to AS when `aud` is the AS; mission state / federation

- **`participants/resource.py`**
  - `POST /authorize` — optional `AAuth-Mission`; mission in resource tokens
  - Protected routes e.g. `GET /data-auth` — auth token verification

- **`participants/auth_server.py`**
  - Mission claim propagation into auth tokens where applicable

- **`participants/agent.py`**
  - PS metadata discovery (`fetch_ps_metadata` / legacy `fetch_mm_metadata_async`)
  - `propose_mission` — verifies `s256` against response body bytes; caches PS `capabilities` for `AAuth-Capabilities`
  - Mission-aware proactive authorize and PS `token_endpoint` routing (`#ps-as-federation`)

### Demo script

- **`demo_phase12.py`**
  - End-to-end: discovery → mission approval → resource token → PS → AS → resource access
  - Asserts `mission.s256` on approval-derived hash, resource token, auth token, and auth token used at the resource

## Testing

```bash
python demo_phase12.py
pytest tests/test_phase12.py -v
```

## Hash verification points

The demo verifies the **`s256`** from **Mission Approval** matches:

1. ✓ Parsed from the `AAuth-Mission` **response** header and checked against the SHA-256 of the **mission blob body** (in `propose_mission`)
2. ✓ Resource token JWT payload `mission.s256`
3. ✓ Auth token JWT payload `mission.s256`
4. ✓ The auth token JWT used for `GET /data-auth` still carries the same `mission.s256` (parsed after a successful response)

All must match the `s256` from mission approval.

## Notes

- Missions are optional; this phase exercises the mission path only.
- Full mission blob content stays between agent and PS; resources and AS see `approver` + `s256` (see **Mission Content Exposure** in SPEC.md).
- Mission approval may be immediate `200` or deferred `202` with clarification — the demo uses immediate approval.
- PS may include **`capabilities`** in the mission blob; the agent unions them with its own for **`AAuth-Capabilities`**.
