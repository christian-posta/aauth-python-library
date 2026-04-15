# Phase 11: PS–AS Trust (Federated Token Path)

Phase 11 demonstrates **PS–AS federation** as defined in [SPEC.md](SPEC.md) — notably **(#ps-as-federation)** and the **Person Server token endpoint** (see “Person Server” / `#person-server` in the spec).

Normative terminology in the spec is **Person Server (PS)** and **`ps`** (the HTTPS URL of the person server in the agent token). This repository’s reference `Agent` still accepts a legacy parameter name `mm_url` as an alias for the same URL; the preferred name is **`ps_url`** (see `participants/agent.py`).

## Overview

### Four-party federated access (SPEC)

1. Agent → Resource (receives `401` + resource token with `aud` = AS URL).
2. Agent → **PS `token_endpoint`** (signed POST with resource token; presents `aa-agent+jwt` via `Signature-Key` where required).
3. PS verifies the resource token, then **POSTs to the AS `token_endpoint`** with its own HTTP Message Signature (`scheme` = `jwks_uri`). The AS verifies the PS and issues `aa-auth+jwt`.
4. PS → Agent (returns auth token).
5. Agent → Resource (access with auth token, e.g. `scheme=jwt`).

Per **SPEC.md**: *“The PS is the only entity that calls AS token endpoints”* in this federation model — the agent does not POST token requests to the AS in the normative four-party path.

### Agent configuration (SPEC)

- The agent’s **`aa-agent+jwt`** MAY include a **`ps`** claim: the Person Server HTTPS URL (SPEC agent tokens).
- The reference implementation sets `ps` from **`ps_url`** / **`mm_url`** when configuring the agent (`Agent._self_issued_agent_token` → `create_agent_token(..., ps=...)`).

### Auth server configuration

- The AS maintains a trust list for Person Servers that may call its `token_endpoint` (in code: `trusted_person_servers=[...]` on `AccessServer`).

## Architecture flow

```mermaid
sequenceDiagram
    participant A as Agent (ps claim)
    participant R as Resource
    participant PS as Person Server
    participant AS as Access Server

    Note over A,R: Step 1: Resource challenge
    A->>R: GET /data-auth (no auth)
    R->>A: 401 + aa-resource+jwt (aud = AS)

    Note over A,PS: Step 2: Agent to PS token_endpoint
    A->>PS: POST /token + resource_token

    Note over PS,AS: Step 3: PS–AS federation
    PS->>PS: Verify resource token
    PS->>AS: POST /token + resource_token (PS HTTPSig jwks_uri)
    AS->>AS: Verify PS in trusted set; issue auth token
    AS->>PS: aa-auth+jwt
    PS->>A: aa-auth+jwt

    Note over A,R: Step 4: Access
    A->>R: request with auth token
    R->>A: 200 OK
```

## What this codebase implements

| Component | Role |
|-----------|------|
| `participants/mission_manager.py` (`PersonServer`) | PS: `POST /token`, metadata at `/.well-known/aauth-person.json` |
| `participants/auth_server.py` (`AccessServer`) | AS: `trusted_person_servers`, verifies PS signature on federated `POST /token` |
| `participants/agent.py` (`Agent`) | `ps_url` / `mm_url` → PS base URL; populates agent token `ps` claim |

## Demo and tests

```bash
python demo_phase11.py
pytest tests/test_phase11.py -v
```

**`demo_phase11.py`** exercises the federated path and asserts SPEC-relevant claims: `ps` on the agent token, `aud` on the resource token (AS URL), and `aa-auth+jwt` from the AS after PS federation.

## Spec cross-references

- Federated access overview: SPEC **#federated-access** / **Figure: Federated Access (Four-Party)**.
- PS–AS federation: **#ps-as-federation**, **#access-server-federation**.
- PS token endpoint: **#ps-token-endpoint** (Person Server section).
- Trust establishment (interaction, payment, claims): **#ps-as-federation** — “PS-AS Trust Establishment”.

## Notes

- The legacy filename `PHASE11-mm-as-trust.md` is kept for continuity; “MM” referred to an older “Mission Manager” name. The spec and code use **Person Server** and **`ps`**.
