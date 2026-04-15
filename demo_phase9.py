"""Demo Phase 9: Interaction Chaining — downstream 202 bubbles back to agent.

A resource (R1) that receives an authorized request calls a downstream resource (R2).
R2's AS requires user consent (202 + interaction).  R1 chains the interaction
back to the original agent: R1 returns its own 202 + pending URL + interaction code.
The user goes to R1's ``/interact`` endpoint, which redirects to R2's AS interact page.
After consent, R1 polls the downstream pending URL, obtains an auth token for R2, and
returns the final 200 to the agent — per SPEC.md (#interaction-chaining) and call chaining
(#call-chaining).
"""

import asyncio
import json
import sys
import threading
from typing import List

from uvicorn import Config, Server

from aauth.tokens.auth_token import parse_token_claims
from participants.agent import Agent
from participants.auth_server import AccessServer
from participants.resource import Resource

_uvicorn_servers: List[Server] = []
_server_threads: List[threading.Thread] = []


def start_uvicorn(app, port: int, name: str) -> None:
    """Run uvicorn in a daemon thread and keep a ``Server`` handle for ``should_exit``."""

    def target() -> None:
        print(f"Starting {name}...", file=sys.stderr, flush=True)
        try:
            config = Config(app, host="0.0.0.0", port=port, log_level="error")
            server = Server(config=config)
            _uvicorn_servers.append(server)
            server.run()
        except Exception as e:
            print(f"{name} error: {e}", file=sys.stderr, flush=True)

    t = threading.Thread(target=target, daemon=True, name=name)
    _server_threads.append(t)
    t.start()


async def shutdown_uvicorn_servers() -> None:
    """Signal all demo servers to exit and wait for threads to finish."""
    if not _uvicorn_servers:
        return
    print("Shutting down servers...", file=sys.stderr, flush=True)
    for s in list(_uvicorn_servers):
        s.should_exit = True
    await asyncio.sleep(2.0)
    for t in _server_threads:
        t.join(timeout=15.0)
    _uvicorn_servers.clear()
    _server_threads.clear()
    print("Done.", file=sys.stderr, flush=True)


def print_port_map(agent, resource1, auth1, resource2, auth2) -> None:
    """Print the 5-server port legend for this demo."""
    rows = [
        (agent.port,     "Agent server",   "iss for agent identity; /.well-known/aauth-agent.json"),
        (resource1.port, "Resource 1",     "iss in R1 resource tokens; /data-chain-auth; /interact"),
        (auth1.port,     "Access Server 1",  "issues auth tokens for R1; direct grant (no consent)"),
        (resource2.port, "Resource 2",       "iss in R2 resource tokens; /data-auth"),
        (auth2.port,     "Access Server 2",  "issues auth tokens for R2; requires user consent"),
    ]
    print("\n" + "-" * 80, file=sys.stderr, flush=True)
    print(
        "127.0.0.1 port map (JWT iss / aud / agent URLs below refer to these):",
        file=sys.stderr,
        flush=True,
    )
    for port, role, detail in rows:
        print(f"  {port:5d}  {role:<22} — {detail}", file=sys.stderr, flush=True)
    print("-" * 80 + "\n", file=sys.stderr, flush=True)


async def main() -> None:
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 9: Interaction Chaining (downstream 202 bubbles back to agent)", file=sys.stderr)
    print(
        "Spec: R1 calls R2 (call chaining); R2's AS requires consent (202 interaction);\n"
        "R1 returns its own 202 to agent; user interacts via R1 → R2's AS; R1 resolves.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource1_id = "http://127.0.0.1:8002"
    auth1_id = "http://127.0.0.1:8003"
    resource2_id = "http://127.0.0.1:8004"
    auth2_id = "http://127.0.0.1:8005"

    agent = Agent(agent_id, port=8001, use_user_simulator=True)
    resource1 = Resource(
        resource1_id,
        port=8002,
        auth_server=auth1_id,
        downstream_resource_url=f"{resource2_id}/data-auth",
    )
    auth1 = AccessServer(auth1_id, port=8003, require_user_consent=False)
    resource2 = Resource(resource2_id, port=8004, auth_server=auth2_id)
    auth2 = AccessServer(
        auth2_id,
        port=8005,
        require_user_consent=True,
        trusted_auth_servers=[auth1_id],
    )

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource1.app, resource1.port, "Resource 1")
    start_uvicorn(auth1.app, auth1.port, "Access Server 1")
    start_uvicorn(resource2.app, resource2.port, "Resource 2")
    start_uvicorn(auth2.app, auth2.port, "Access Server 2")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_port_map(agent, resource1, auth1, resource2, auth2)

    try:
        # ------------------------------------------------------------------
        print(
            "TEST 1: Agent → R1 (/data-chain-auth) → R2 with interaction chaining",
            file=sys.stderr,
        )

        response = await agent.request_resource(
            resource_url=f"{resource1_id}/data-chain-auth",
            method="GET",
            sig_scheme="jwks_uri",
        )
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert data.get("token_type") == "aa-auth+jwt"
        print("  ✓ TEST 1 PASSED: Interaction chain resolved, agent received 200", file=sys.stderr)
        print(f"  Final response: {data}", file=sys.stderr)

        # Display auth token the agent received for Resource 1 (from AS1).
        auth_token = agent.auth_token
        assert auth_token, "Agent should have stored auth_token"
        ac = parse_token_claims(auth_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN for R1 (aa-auth+jwt, issued by AS1) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(ac["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(ac["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Display the downstream auth token R1 obtained for R2 (from AS2).
        downstream_token = resource1.last_downstream_auth_token
        assert downstream_token, "Resource 1 should have stored downstream auth token"
        dc = parse_token_claims(downstream_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("DOWNSTREAM AUTH TOKEN for R2 (aa-auth+jwt, issued by AS2) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(dc["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(dc["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # ------------------------------------------------------------------
        print("\nTEST 2: Verify token chain claims", file=sys.stderr)

        # Agent auth token: AS1 issued for R1 (agent may be aauth:… or HTTPS URL per deployment)
        assert ac["header"].get("typ") == "aa-auth+jwt"
        assert ac["payload"].get("iss") == auth1_id
        assert ac["payload"].get("aud") == resource1_id
        agent_claim_r1 = ac["payload"].get("agent")
        assert agent_claim_r1, "R1 auth token must carry agent"
        print(
            f"  ✓ R1 auth token: iss={auth1_id}, aud={resource1_id}, agent={agent_claim_r1}",
            file=sys.stderr,
        )

        # Downstream auth token: AS2 issued for R2, agent is R1
        assert dc["header"].get("typ") == "aa-auth+jwt"
        assert dc["payload"].get("iss") == auth2_id
        assert dc["payload"].get("aud") == resource2_id
        assert dc["payload"].get("agent") == resource1_id, (
            f"Expected downstream agent={resource1_id!r}, got {dc['payload'].get('agent')!r}"
        )
        print(
            f"  ✓ R2 auth token: iss={auth2_id}, aud={resource2_id}, agent={resource1_id}",
            file=sys.stderr,
        )

        # Nested delegation chain (SPEC.md — auth token act claim)
        act = dc["payload"].get("act")
        assert isinstance(act, dict), "Downstream auth token must include act claim"
        assert act.get("sub") == resource1_id, "act.sub must be the intermediary (R1)"
        inner = act.get("act")
        assert isinstance(inner, dict), "Call chaining must nest upstream act"
        assert inner.get("sub") == agent_claim_r1, (
            "Nested act.sub must match the upstream auth token agent identity"
        )
        assert dc["payload"].get("cnf", {}).get("jwk"), "cnf.jwk must bind R1's signing key"
        print(
            f"  ✓ act chain: act.sub={act.get('sub')!r} → act.act.sub={inner.get('sub')!r}",
            file=sys.stderr,
        )
        print("  ✓ TEST 2 PASSED: Full call chain verified (agent→R1→R2 identity preserved)", file=sys.stderr)

        print("\nPhase 9 interaction chaining demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
