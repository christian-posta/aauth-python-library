# Demo scripts and spec coverage

Normative reference for current protocol behavior in this repo: **`SPEC_UPDATED.md`**. Exploratory / older narrative lives in **`SPEC.md`**.

## Phase scripts

| Script | SPEC_UPDATED.md (approx.) |
|--------|---------------------------|
| `demo_phase1.py` | Section 4.5.1 Pseudonymous access (`scheme=hwk`) |
| `demo_phase2.py` | Section 4.5.2 Agent identity (`jwks_uri`; `hwk` on an alternate route) |
| `demo_phase3.py` | Section 4.5.3 Autonomous agent; 401 + resource token → token endpoint → 200 |
| `demo_phase4.py` | Section 4.5.4 User authorization: challenge, token `POST`, **202 + `Location`**, interaction code, **polling**, retry with auth token |
| `demo_phase5.py` | Missions: MM proposal/approval, **`AAuth-Mission`**, mission in tokens |
| `demo_phase6.py` | Agent tokens (Section 7); delegate `scheme=jwt` |
| `demo_phase7.py` | MM–AS federation, `upstream_token` / call chaining |
| `demo_phase8.py` | Section 11.4 Clarification chat (polling `clarification` + POST `clarification_response`) |
| `demo_phase9.py` | Section 4.5.8.2 Interaction chaining (downstream interaction bubbled via Resource 1) |
| `demo_phase10.py` | Resource **`authorization_endpoint`**, proactive **`POST /authorize`**, metadata |
| `demo_phase11.py` | MM–AS trust: agent → MM → AS with trusted MM signing |
| `demo_phase12.py` | Mission lifecycle: propose → resource token w/ mission → auth via MM |

`demo_phase8.py` now covers clarification chat. Additional behaviors are listed below as remaining gaps.

## Gaps (not covered by `demo_phase*`)

These spec areas are either not fully scripted or still partial in this codebase:

- **Section 4.5.6 Direct approval** — `require=approval`: agent polls only; limited interaction UX.
- **Section 4.5.7 Resource interaction** — resource returns **202** + interaction code (deferral at the resource) — partial.
- **Sections 10 / 18.4 Terminal polling** — scripted demos for 403 (denied / abandoned), 408 (expired), 410 (invalid code).
- **Section 11.6 Token refresh** — `POST` token with expired `auth_token`; token refresh handling is not fully implemented on the demo auth server.

**Covered in part:** Section 8 **`authorization_endpoint`** / proactive resource tokens — see **`demo_phase10.py`**.

**Optional / advanced:** Section 7.1 agent token `aud` / `aud_sub`; Section 15.3 `additional_signature_components` on resources.
