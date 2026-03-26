# Phase 8: Clarification Chat

Phase 8 adds demo coverage for **SPEC_UPDATED.md Section 11.4**. During deferred consent polling, the auth server can include a `clarification` question in a `202` polling response. The agent replies by sending `POST /pending/{id}` with `clarification_response`.

## Flow Description

1. Agent requests protected resource and receives `401` challenge with `resource_token`.
2. Agent sends signed `POST /token` to auth server.
3. Auth server returns `202` with `Location` pending URL (`require=interaction`).
4. Agent polls `GET /pending/{id}` and receives `202` including `clarification`.
5. Agent sends signed `POST /pending/{id}` with:

```json
{
  "clarification_response": "This agent only requests access to fulfill the current task and uses the minimum required scope."
}
```

6. User grants consent at `/interact`.
7. Agent polling receives terminal `200` with `auth_token`.
8. Agent retries original resource request with `sig=jwt`.

## What was implemented

- `participants/agent.py`
  - Publishes `clarification_supported` in agent metadata.
  - Wires clarification callbacks into the poller.
  - Sends signed `POST` requests to pending URL for clarification responses.
- `participants/auth_server.py`
  - Tracks clarification support per pending request.
  - Includes `clarification` in pending polling responses when applicable.
  - Persists clarification response history and enforces a round limit.
- `demo_phase8.py`
  - End-to-end clarification round-trip demo.
- `tests/test_phase8.py`
  - Coverage for metadata support flags and pending clarification behavior.

## Running

```bash
python demo_phase8.py
pytest tests/test_phase8.py -v
```
