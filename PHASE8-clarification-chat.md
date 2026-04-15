# Phase 8: Clarification Chat

Phase 8 adds demo coverage for **SPEC.md** [Clarification Chat](SPEC.md) (including `requirement=clarification` and the pending-URL clarification response). During deferred consent, while the agent polls `GET /pending/{id}`, the auth server may return `202` responses whose JSON body includes a `clarification` question. The agent answers with a signed `POST /pending/{id}` carrying `clarification_response`.

## Flow description (aligned with `demo_phase8.py` TEST 1)

1. Agent requests the protected resource and receives `401` with `AAuth-Requirement: requirement=auth-token` and a `resource_token`.
2. Agent sends a signed `POST /token` to the auth server with `resource_token`.
3. Auth server returns `202` with `Location` pointing at the pending URL. The JSON body includes `requirement=interaction` and an interaction `code` (and the response headers include the corresponding `AAuth-Requirement` for interaction).
4. Agent polls `GET /pending/{id}`. While consent is still pending and the agent is marked as supporting clarification, polls can return `202` whose body includes `clarification` (the question text) and whose headers include `AAuth-Requirement: requirement=clarification` per SPEC.md.
5. Agent sends a signed `POST /pending/{id}` with:

```json
{
  "clarification_response": "This agent only requests access to fulfill the current task and uses the minimum required scope."
}
```

6. User grants consent at `/interact?code=…`.
7. Further polling receives terminal `200` with `auth_token`.
8. Agent retries the original resource request using `sig=jwt` with the stored auth token.

### How TEST 1 orders consent vs clarification

`demo_phase8.py` runs the agent with **`auto_interact=False`**: the agent does **not** open or complete `/interact` when it first sees `requirement=interaction`. The demo waits until the agent has posted a clarification response (observed via `clarification_history` on the pending request), **then** drives `UserSimulator.complete_interaction` against `/interact`. That ordering avoids approving consent before the clarification round-trip. A second agent (`TEST 2`) uses the built-in user simulator on the normal path without that split.

## TEST 2 (unsupported agent)

A second agent declares `clarification_supported=False` in metadata and omits `clarification` from default `AAuth-Capabilities`. The auth server skips sending clarification on pending polls; the agent still obtains an auth token after consent and never records clarification history.

## What was implemented

- `participants/agent.py`
  - Publishes `clarification_supported` in agent metadata and aligns default `AAuth-Capabilities` with that flag.
  - Wires clarification callbacks into the poller; sends signed `POST` to the pending URL for clarification responses.
  - `auto_interact` controls whether the agent handles interaction (consent URL) automatically on the initial `202` from `/token`.
- `participants/auth_server.py`
  - Discovers clarification support using the agent **server** HTTP URL (well-known metadata), not the `aauth:…` subject.
  - Tracks clarification support per pending request; includes `clarification` in polling `202` bodies when applicable and sets `AAuth-Requirement: requirement=clarification` for those responses.
  - Persists clarification response history and enforces a round limit.
- `demo_phase8.py`
  - End-to-end clarification round-trip (TEST 1) and no-clarification path (TEST 2).
- `tests/test_phase8.py`
  - Coverage for metadata support flags and pending clarification behavior.

## Running

```bash
python3 demo_phase8.py
pytest tests/test_phase8.py -v
```
