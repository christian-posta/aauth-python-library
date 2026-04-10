# Phase 5: Missions

Phase 5 demonstrates **mission proposals**, MM approval (**`s256`** digest of approved text), and carrying mission context via the **`AAuth-Mission`** header on resource requests so **resource tokens** and **auth tokens** can include an optional **`mission`** object (`manager` + `s256`).

Earlier iterations of this repo documented “agent as resource” (self-access via `scope` only) under `PHASE5-agent-is-resource.md`. That flow remains available through **`Agent.request_self_authorization()`** and auth-server token modes; the primary Phase 5 narrative is now missions per **SPEC_UPDATED.md** (missions + Mission Manager).

## Automated pieces

1. **`Agent.propose_mission(text)`** → **`POST`** MM **`mission_endpoint`** with **`mission_proposal`**.
2. MM returns **`mission.s256`** and approved markdown text; agent caches **`approved_mission`**.
3. **`Agent.request_resource_token_proactively(resource_url, scope)`** → **`POST`** resource **`authorization_endpoint`** with optional **`AAuth-Mission`** built from the cache.
4. Resource embeds **`mission`** in the **aa-resource+jwt** when the header is present.

See **`demo_phase5.py`** and **`demo_phase10.py`**–**`demo_phase12.py`** for orchestrated examples.
