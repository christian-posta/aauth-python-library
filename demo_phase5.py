"""Demo Phase 5: Missions — PS approval, AAuth-Mission, mission in resource token.

Replaces the older "agent-as-resource" Phase 5 demo. For self-access / scope-only
tokens see PHASE5-agent-is-resource.md and ``Agent.request_self_authorization``.

What this demo shows (all spec-compliant):
  1. Agent proposes a mission to the PS with a Markdown description and tool list.
  2. PS verifies the agent token (scheme=jwt), builds the mission blob, computes
     s256 = SHA-256(blob_bytes), and returns blob + AAuth-Mission response header.
  3. Agent verifies the s256 against the raw response bytes and caches the approval.
  4. Agent includes AAuth-Mission header on the proactive resource request.
  5. Resource embeds the mission object (approver + s256) in the resource token JWT.
"""

import asyncio
import json
import sys
import threading
from typing import List

import jwt
from uvicorn import Config, Server

from participants.agent import Agent
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
from participants.resource import Resource

_uvicorn_servers: List[Server] = []
_server_threads: List[threading.Thread] = []


def start_uvicorn(app, port: int, name: str) -> None:
    """Run uvicorn in a daemon thread and keep a Server handle for should_exit."""

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


def sep(title: str = "") -> None:
    line = "─" * 72
    if title:
        print(f"\n{line}", file=sys.stderr)
        print(f"  {title}", file=sys.stderr)
        print(f"{line}", file=sys.stderr)
    else:
        print(f"{line}", file=sys.stderr)


async def main():
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 72, file=sys.stderr)
    print("  Phase 5: Missions — spec-compliant flow", file=sys.stderr)
    print("=" * 72 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    agent = Agent(agent_id, port=8001, mm_url=ps_id)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AccessServer(as_id, port=8003, trusted_person_servers=[ps_id])
    ps = PersonServer(ps_id, port=8004)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Access Server")
    start_uvicorn(ps.app, ps.port, "Person Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    try:
        # ── TEST 1: Mission proposal ──────────────────────────────────────────
        sep("TEST 1: Agent proposes a mission to the PS")

        description = (
            "# Analyze Q2 Customer Feedback\n\n"
            "Read customer feedback submissions for Q2, identify top themes,\n"
            "and produce a summary report. Do NOT modify any records."
        )
        tools = [
            {"name": "FeedbackReader", "description": "Read customer feedback records"},
            {"name": "ReportWriter", "description": "Write the summary report"},
        ]

        print("\nProposal body sent to PS /mission:", file=sys.stderr)
        print(json.dumps({"description": description, "tools": tools}, indent=2), file=sys.stderr)

        approved = await agent.propose_mission(description=description, tools=tools)
        assert approved and approved.get("s256"), "Mission proposal failed"

        print("\nApproved mission (from PS response):", file=sys.stderr)
        # Retrieve the full blob stored by the PS for display
        s256 = approved["s256"]
        blob = ps.missions[s256]["blob"]
        print(json.dumps(blob, indent=2), file=sys.stderr)

        print(f"\nAAuth-Mission response header from PS:", file=sys.stderr)
        print(f'  AAuth-Mission: approver="{approved["approver"]}"; s256="{s256[:32]}..."', file=sys.stderr)

        print(f"\n✓ s256 verified (SHA-256 of blob bytes): {s256[:32]}...", file=sys.stderr)

        # Show the capabilities the PS declared and what the agent will advertise
        ps_caps = agent.ps_capabilities
        all_caps = list(dict.fromkeys(agent.capabilities + ps_caps))
        print(f"\nCapabilities:", file=sys.stderr)
        print(f"  Agent own     : {agent.capabilities}", file=sys.stderr)
        print(f"  PS (from blob): {ps_caps}", file=sys.stderr)
        print(f"  Union (→ AAuth-Capabilities header): {all_caps}", file=sys.stderr)

        # ── TEST 2: Proactive resource token includes mission claim ───────────
        sep("TEST 2: Agent requests resource token — AAuth-Mission → mission in JWT")

        # Show what goes out on the wire to the resource
        from aauth.headers.aauth_header import build_aauth_mission_header, build_aauth_capabilities_header
        mission_hdr = build_aauth_mission_header(approved["approver"], s256)
        caps_hdr = build_aauth_capabilities_header(all_caps)
        print(f"\nHeaders sent to resource /authorize:", file=sys.stderr)
        print(f"  AAuth-Mission      : {mission_hdr[:80]}...", file=sys.stderr)
        print(f"  AAuth-Capabilities : {caps_hdr}", file=sys.stderr)

        rt = await agent.request_resource_token_proactively(resource_id, "data.read")
        assert rt, "Resource token request failed"

        hdr = jwt.get_unverified_header(rt)
        payload = jwt.decode(rt, options={"verify_signature": False})

        assert hdr.get("typ") == "aa-resource+jwt", f"Unexpected typ: {hdr.get('typ')}"
        mission_claim = payload.get("mission")
        assert mission_claim and mission_claim.get("approver") and mission_claim.get("s256"), \
            "mission claim missing from resource token"

        print(f"\nDecoded resource token (aa-resource+jwt) payload:", file=sys.stderr)
        print(json.dumps(payload, indent=2), file=sys.stderr)

        print(f"\n✓ mission claim in resource token:", file=sys.stderr)
        print(f"    approver : {mission_claim['approver']}", file=sys.stderr)
        print(f"    s256     : {mission_claim['s256'][:32]}...", file=sys.stderr)

        sep()
        print("Phase 5 demo complete — all spec checks passed.\n", file=sys.stderr)

    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
