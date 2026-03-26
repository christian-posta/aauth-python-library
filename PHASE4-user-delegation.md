# Phase 4: User Delegation

![Phase 4 Demo Screenshot](images/demo4.png)

Phase 4 implements user-delegated access aligned with **SPEC_UPDATED.md** (Sections 4.5.4, 10, 11). When the auth server requires consent, it does **not** return a `request_token` or OAuth **authorization code**. It returns **202 Accepted** with a **pending URL** (`Location`) and an **interaction code**. The user completes login/consent at **`/interact`**, and the agent obtains the **auth token** only by **polling** the pending URL with signed **GET** requests.

## Flow Description

### Automated flow (user simulator)

1. **Agent requests resource** (e.g. `GET /data-auth` with `sig=jwks_uri`).
2. **Resource** returns **401** with **AAuth** (or legacy `Agent-Auth`) challenge including `resource_token` and `auth_server`.
3. **Agent** sends signed **POST** to the auth server **`/token`** with JSON body `{"resource_token": "..."}` (and optional `purpose`, etc.).
4. **Auth server** returns **202** with JSON `status`, `location`, `require=interaction`, and `code` (interaction code).
5. **User simulator** drives **GET/POST** `{auth_server}/interact?code=...` (login + consent).
6. **Agent** **polls** `GET {location}` until **200** with `auth_token` in the body.
7. **Agent** retries the resource with **`scheme=jwt`** (auth token). Resource returns **200**.

There is **no** `request_token` string and **no** token delivery via `?code=` on the agent callback.

### Manual flow (browser)

Same protocol as above: open **`{auth_server}/interact?code=<interaction_code>`** (and optional `callback=`). After consent, the agent receives the token via **polling**, not from the redirect. See **`demo_phase4.py`** and **[DEMOS.md](DEMOS.md)**.

## Key features

| Concept | Behavior in this repo |
|--------|-------------------------|
| Pending state | `pending_requests[pending_id]` holds agent, resource, scope, `interaction_code`, `agent_jwk`, status |
| Interaction | Short **interaction code** in 202 body / **AAuth** header; user visits **`/interact`** |
| Token delivery | **GET** pending URL until terminal **200** with `auth_token` |
| User identity | Auth token includes **`sub`** after consent |

## Testing

```bash
python demo_phase4.py
pytest tests/test_phase4.py -v
```

Integration placeholder (requires servers): `pytest -m integration tests/test_phase4.py`

## What was implemented (reference)

- **`participants/auth_server.py`**: `POST /token`, **202** + **`/pending/{id}`**, **GET/POST** `/interact`, pending storage in `pending_requests`.
- **`participants/agent.py`**: `_handle_deferred_response`, polling via **`aauth.agent.poller`**.
- **`participants/user_simulator.py`**: Completes **`/interact`** forms (not `/agent/auth`).
- **`flows/user_delegated.py`**: Orchestrates automated delegation flow.

Normative detail: **SPEC_UPDATED.md**. Demo/spec index: **DEMOS.md**.
