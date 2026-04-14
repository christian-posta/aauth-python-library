# Phase 5 (legacy): Agent is Resource

> **Note:** The main Phase 5 narrative is now **missions** — see **[PHASE5-missions.md](PHASE5-missions.md)**. This file retains the older **agent-as-audience** write-up for **`request_self_authorization()`** / scope-only token requests.

Phase 5 originally highlighted **agent as audience** (SPEC_UPDATED.md Section 4.5.5): the agent requests an auth token for **itself** using **`scope`** only (no `resource_token`). The auth token uses **`aud`** = agent identifier and omits the **`agent`** claim. User consent still uses the same **deferred** mechanism as Phase 4: **202**, pending URL, **interaction code**, **`/interact`**, and **polling** — not `request_token` or authorization code exchange.

## Flow description

### Automated flow (user simulator)

1. **Agent** calls **`request_self_authorization()`**: signed **POST** to **`/token`** with JSON `{"scope": "profile email"}` (no `resource_token`).
2. **Auth server** validates the agent, requires consent → **202** + pending URL + interaction **code**.
3. **User simulator** completes **`/interact`** (login + consent).
4. **Agent** **polls** the pending URL until **200** with **`auth_token`**.
5. Verify claims: **`aud`** = agent id, **`agent`** omitted, **`sub`** present, **`scope`** matches.

### Manual flow

Open **`{auth_server}/interact?code=<code>`** after the agent receives **202**. Token arrives via **polling**; callback URL is optional UX only (SPEC_UPDATED Section 19.9).

## Key features

### Direct authorization request

- JSON body to **`/token`** with **`scope`** (no `resource_token`) for self-access (SPEC_UPDATED Section 11.1, Table 3).
- Auth server treats the agent identifier as the resource audience when issuing the token.

### Unified auth token (when agent is resource)

- **`aud`**: agent identifier.
- **`agent`**: omitted for this mode.
- **`sub`**: user identifier after consent.
- **`scope`**: granted scopes.
- **`cnf.jwk`**: bound signing key.

### Compared to Phase 4

| Aspect | Phase 4 | Phase 5 |
|--------|---------|---------|
| Token request body | `resource_token` | `scope` (no `resource_token`) |
| Resource | Separate resource URL | Agent itself |
| **`aud`** in auth token | Resource identifier | Agent identifier |
| **`agent`** claim | Present | Omitted |
| Consent mechanism | 202 + interact + poll | Same |

## Testing

```bash
python demo_phase5.py
pytest tests/test_phase5.py -v
```

## What was implemented (reference)

- **`participants/auth_server.py`**: Self-access branch on **`/token`**, **`agent_is_resource`** flag on pending + token issuance.
- **`participants/agent.py`**: **`request_self_authorization()`** — same deferred/polling path as resource-token flow.
- **`aauth/tokens/`** (and signing): **`aa-auth+jwt`** with conditional **`agent`** claim.
- **`demo_phase5.py`**: Claim checks for Phase 5 tokens.

See **SPEC_UPDATED.md** and **DEMOS.md** for normative behavior and demo coverage.
