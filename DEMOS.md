# Demo scripts and spec coverage

Normative reference for current protocol behavior in this repo: **`SPEC_UPDATED.md`**. Exploratory / older narrative lives in **`SPEC.md`**.

## Phase scripts

| Script | SPEC_UPDATED.md (approx.) |
|--------|---------------------------|
| `demo_phase1.py` | Section 4.5.1 Pseudonymous access (`scheme=hwk`) |
| `demo_phase2.py` | Section 4.5.2 Agent identity (`jwks_uri`; `hwk` on an alternate route) |
| `demo_phase3.py` | Section 4.5.3 Autonomous agent; 401 + resource token → token endpoint → 200; optional `txn` |
| `demo_phase4.py` | Section 4.5.4 User authorization: challenge, token `POST`, **202 + `Location`**, interaction code, **polling**, retry with auth token |
| `demo_phase5.py` | Section 4.5.5 Agent as audience (`scope` only, no `resource_token`) |
| `demo_phase6.py` | Agent tokens (Section 7); delegate `scheme=jwt` |
| `demo_phase7.py` | Section 4.5.8.1 Call chaining (direct grant), `upstream_token` |

There is **no** `demo_phase8.py`. Additional behaviors are listed below as gaps.

## Gaps (not covered by `demo_phase*`)

These spec areas are either not scripted as demos or depend on features still incomplete in this codebase:

- **Section 4.5.6 Direct approval** — `require=approval`: agent polls only; no interaction redirect.
- **Section 4.5.7 Resource interaction** — resource returns **202** + interaction code (deferral at the resource, not only at the auth server).
- **Section 4.5.8.2 Interaction chaining** — downstream user interaction forwarded via Resource 1’s interaction endpoint.
- **Section 8.3 Resource token endpoint** — proactive `POST` for a resource token **without** a prior 401 challenge.
- **Sections 10 / 18.4 Terminal polling** — scripted demos for 403 (denied / abandoned), 408 (expired), 410 (invalid code).
- **Section 11.4 Clarification chat** — full round-trip (poll carries `clarification`, agent `POST`s `clarification_response`).
- **Section 11.6 Token refresh** — `POST` token with expired `auth_token`; token refresh handling is not fully implemented on the demo auth server.

**Optional / advanced:** Section 7.1 agent token `aud` / `aud_sub`; Section 15.3 `additional_signature_components` on resources.
