"""Demo Phase 11: PS–AS trust — federated token path (SPEC #ps-as-federation).

Normative flow (four-party, SPEC.md):

- The agent's ``aa-agent+jwt`` MAY include a ``ps`` claim (Person Server HTTPS URL).
- The resource issues a resource token with ``aud`` = the Access Server (AS) URL.
- The agent POSTs the resource token to the PS ``token_endpoint`` (HTTPSig + agent token),
  not to the AS. The PS verifies the resource token and federates to the AS; the AS
  trusts the PS (``trusted_person_servers``) and issues ``aa-auth+jwt``.

Per SPEC: "The PS is the only entity that calls AS token endpoints" for this federation
path — the demo does not show a direct agent→AS token POST as a supported alternative.

The reference ``Agent`` accepts ``ps_url`` (preferred) or legacy ``mm_url`` for the PS
base URL; that value is placed in the agent token ``ps`` claim (see ``_self_issued_agent_token``).
"""

import asyncio
import json
import sys
import threading
from typing import List

from uvicorn import Config, Server

from aauth.debug import print_stderr_localhost_port_map
from aauth.identifiers import agent_identifier_from_server_url
from aauth.tokens.auth_token import parse_token_claims
from participants.agent import Agent
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
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


async def main() -> None:
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 11: PS–AS trust (federated token path per SPEC #ps-as-federation)", file=sys.stderr)
    print(
        "Spec: Agent POSTs resource token to PS token_endpoint; PS signs to AS\n"
        "(HTTPSig jwks_uri); AS verifies PS identity (trusted_person_servers) and issues auth token.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    # Agent with PS configured (ps claim + routing to PS token_endpoint).
    agent = Agent(agent_id, port=8001, ps_url=ps_id)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AccessServer(as_id, port=8003, trusted_person_servers=[ps_id])
    ps = PersonServer(ps_id, port=8004)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Access Server")
    start_uvicorn(ps.app, ps.port, "Person Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_stderr_localhost_port_map(agent, resource, auth)

    try:
        # ------------------------------------------------------------------
        print(
            "TEST 1: Four-party flow — 401 challenge → PS token_endpoint → AS → aa-auth+jwt",
            file=sys.stderr,
        )

        response = await agent.request_resource(
            resource_url=f"{resource_id}/data-auth",
            method="GET",
            sig_scheme="jwks_uri",
        )
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert data.get("token_type") == "aa-auth+jwt"

        # Display the resource token the agent captured from the 401 challenge.
        rt = agent.resource_token
        assert rt, "Agent should have captured resource token from 401 challenge"
        rt_claims = parse_token_claims(rt)
        print("\n" + "=" * 80, file=sys.stderr)
        print("RESOURCE TOKEN (aa-resource+jwt) — captured from 401 challenge", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(rt_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(rt_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Display the auth token the PS obtained from the AS.
        auth_token = agent.auth_token
        assert auth_token, "Agent should have stored auth_token"
        at_claims = parse_token_claims(auth_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — issued by AS after PS federation", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(at_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(at_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Verify token chain
        assert at_claims["header"].get("typ") == "aa-auth+jwt"
        assert at_claims["payload"].get("iss") == as_id
        assert at_claims["payload"].get("aud") == resource_id
        expected_agent_aauth = agent_identifier_from_server_url(agent_id)
        assert at_claims["payload"].get("agent") == expected_agent_aauth, (
            f"auth token agent claim must be aauth: form (SPEC): got {at_claims['payload'].get('agent')!r}"
        )
        print("  ✓ TEST 1 PASSED: PS-federated auth token; resource returned 200", file=sys.stderr)
        print(f"  Final response: {data}", file=sys.stderr)

        # ------------------------------------------------------------------
        print(
            "\nTEST 2: SPEC alignment — ps claim on agent token; aud on resource token (four-party)",
            file=sys.stderr,
        )

        agent_jwt = agent._self_issued_agent_token()
        ag_claims = parse_token_claims(agent_jwt)
        assert ag_claims["header"].get("typ") == "aa-agent+jwt"
        assert ag_claims["payload"].get("ps") == ps_id, (
            "Agent token must carry ps claim matching the configured Person Server (SPEC)"
        )
        assert rt_claims["payload"].get("aud") == as_id, (
            "Four-party: resource token aud must be the AS URL (SPEC federated access)"
        )
        print(f"  ✓ Agent token ps claim: {ag_claims['payload'].get('ps')}", file=sys.stderr)
        print(f"  ✓ Resource token aud:   {rt_claims['payload'].get('aud')}", file=sys.stderr)
        print(
            "  ✓ TEST 2 PASSED: ps + four-party aud match SPEC bootstrapping / PS-AS federation",
            file=sys.stderr,
        )

        print("\nPhase 11 PS–AS trust demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
