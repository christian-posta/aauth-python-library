# Phase 9: Interaction Chaining

Phase 9 adds demo coverage for **SPEC_UPDATED.md Section 4.5.8.2**.

When downstream authorization requires user interaction, Resource 1 bubbles a deferred interaction back to the original agent:

1. Resource 1 receives downstream `202 require=interaction`.
2. Resource 1 returns its own `202` with local pending URL and interaction code.
3. Agent directs user to Resource 1 `/interact`.
4. Resource 1 redirects user to downstream auth server interaction endpoint.
5. Resource 1 polls downstream pending URL and returns terminal result to the agent.

## What was implemented

- `participants/resource.py`
  - Added `GET /data-chain-auth` for Resource-1 mediated downstream access.
  - Added local chained pending state (`chained_pending_requests`).
  - Added `GET /pending/{id}` for agent polling against Resource 1.
  - Added `GET /interact` for Resource-1 interaction redirect to downstream auth.
  - Added downstream authorization helper handling direct token or deferred interaction.
- `participants/agent.py`
  - Added handling for deferred `202` responses returned by resources.
  - Added resource-pending polling loop with optional user simulator interaction.
- `participants/user_simulator.py`
  - Updated initial interaction GET to follow redirects, enabling chained interaction UX.
- `demo_phase9.py`
  - End-to-end phase demo with Agent -> Resource 1 -> Resource 2 + downstream interaction.
- `tests/test_phase9.py`
  - Tests for Resource 1 interaction redirect and pending endpoint basics.

## Running

```bash
python demo_phase9.py
pytest tests/test_phase9.py -v
```
