"""Demo script for Phase 3: Autonomous Authorization."""

import asyncio
import sys
import threading
import traceback
from typing import List

from uvicorn import Config, Server

from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
from flows.autonomous import run_autonomous_flow
from aauth.debug import print_stderr_localhost_port_map
from aauth.keys.jwk import public_key_to_jwk
from aauth.tokens.agent_token import create_agent_token
from aauth.tokens.auth_token import parse_token_claims

# Filled by ``start_uvicorn`` threads; used for graceful shutdown.
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
    # ``Server.on_tick`` checks ``should_exit`` roughly every 0.1s; allow shutdown + lifespan.
    await asyncio.sleep(2.0)
    for t in _server_threads:
        t.join(timeout=15.0)
    _uvicorn_servers.clear()
    _server_threads.clear()
    print("Done.", file=sys.stderr, flush=True)


async def main():
    """Run Phase 3 demo."""
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 3: Autonomous Authorization Demo", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("\nThis demo shows the autonomous authorization flow (spec-compliant path):", file=sys.stderr)
    print("1. Agent requests resource (gets resource token challenge)", file=sys.stderr)
    print("2. Agent sends resource token to Person Server token endpoint", file=sys.stderr)
    print("3. PS federates to the access server; AS issues auth token to PS response", file=sys.stderr)
    print("4. Agent retries resource request with auth token", file=sys.stderr)
    print("5. Resource validates auth token and grants access", file=sys.stderr)
    print("\nTest 1: Standard flow", file=sys.stderr)
    print("Test 2: Verify dwk on agent, resource, and auth tokens (spec agent / resource / auth sections)", file=sys.stderr)
    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    auth_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    agent = Agent(agent_id, port=8001, mm_url=ps_id)
    resource = Resource(resource_id, port=8002, auth_server=auth_id)
    auth_server = AccessServer(auth_id, port=8003, trusted_person_servers=[ps_id])
    ps = PersonServer(ps_id, port=8004, require_user_consent=False)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth_server.app, auth_server.port, "Access Server")
    start_uvicorn(ps.app, ps.port, "Person Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    print_stderr_localhost_port_map(agent, resource, auth_server)

    try:
        test_results = []

        # =========================================================================
        # Test 1: Standard autonomous authorization flow
        # =========================================================================
        print("\n" + "=" * 80, file=sys.stderr)
        print("TEST 1: Autonomous Authorization Flow", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Description: Standard flow. Verifies auth token is issued with", file=sys.stderr)
        print("             correct dwk and jti claims per updated spec.", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)

        test1_passed = False
        test1_error = None

        try:
            response = await run_autonomous_flow(
                agent=agent,
                resource=resource,
                auth_server=auth_server,
                resource_url=f"{resource_id}/data-auth",
                method="GET",
            )

            if response.status_code == 200:
                data = response.json()
                print(f"\n  Access granted: {data.get('message')}", file=sys.stderr)

                auth_token = agent.auth_token
                if auth_token:
                    claims = parse_token_claims(auth_token)
                    payload = claims["payload"]

                    print(f"\n  Auth token claims:", file=sys.stderr)
                    print(f"    jti: {payload.get('jti')}", file=sys.stderr)
                    print(f"    dwk: {payload.get('dwk', '(not present)')}", file=sys.stderr)

                    if payload.get("dwk") == "aauth-access.json" and "jti" in payload:
                        test1_passed = True
                        print(f"\n  ✓ dwk correctly set to aauth-access.json", file=sys.stderr)
                        print(f"  ✓ jti present for replay detection", file=sys.stderr)
                    elif payload.get("dwk") != "aauth-access.json":
                        test1_error = f"dwk should be 'aauth-access.json', got: {payload.get('dwk')}"
                        print(f"\n  ✗ dwk incorrect: {payload.get('dwk')}", file=sys.stderr)
                    else:
                        test1_error = "jti should be present in auth token"
                        print(f"\n  ✗ jti missing from auth token", file=sys.stderr)
                else:
                    test1_error = "No auth token stored on agent"
            else:
                test1_error = f"Status {response.status_code}: {response.text}"
                print(f"\n✗ TEST 1 FAILED: Status {response.status_code}", file=sys.stderr)

        except Exception as e:
            test1_error = str(e)
            print(f"\n✗ TEST 1 FAILED: {e}", file=sys.stderr, flush=True)
            traceback.print_exc()

        status = "✓ PASSED" if test1_passed else "✗ FAILED"
        print(f"\n{status}: TEST 1: Autonomous Authorization Flow", file=sys.stderr)
        test_results.append(("TEST 1: Autonomous Authorization", test1_passed, test1_error))

        # =========================================================================
        # Test 2: Verify dwk claims in tokens
        # =========================================================================
        print("\n" + "=" * 80, file=sys.stderr)
        print("TEST 2: Verify dwk Claims in Tokens", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Description: Verify agent, resource, and auth tokens carry the correct", file=sys.stderr)
        print("             dwk claim for {iss}/.well-known/{dwk} discovery.", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)

        agent.auth_token = None

        test2_passed = False
        test2_error = None

        try:
            response = await run_autonomous_flow(
                agent=agent,
                resource=resource,
                auth_server=auth_server,
                resource_url=f"{resource_id}/data-auth",
                method="GET",
            )

            if response.status_code != 200:
                test2_error = f"Status {response.status_code}: {response.text}"
                print(f"\n✗ TEST 2 FAILED: Status {response.status_code}", file=sys.stderr)
            else:
                errs = []

                rt = agent.resource_token
                if not rt:
                    errs.append("No resource token stored on agent")
                else:
                    rtp = parse_token_claims(rt)["payload"]
                    rdwk = rtp.get("dwk")
                    print(f"\n  Resource token dwk: {rdwk or '(not present)'}", file=sys.stderr)
                    if rdwk != "aauth-resource.json":
                        errs.append(f"resource token dwk: expected aauth-resource.json, got {rdwk!r}")

                auth_token = agent.auth_token
                if not auth_token:
                    errs.append("No auth token stored on agent")
                else:
                    atp = parse_token_claims(auth_token)["payload"]
                    adwk = atp.get("dwk")
                    print(f"  Auth token dwk: {adwk or '(not present)'}", file=sys.stderr)
                    if adwk != "aauth-access.json":
                        errs.append(f"auth token dwk: expected aauth-access.json, got {adwk!r}")

                cnf_jwk = public_key_to_jwk(agent.public_key, kid=agent.kid)
                sample_agent_jwt = create_agent_token(
                    iss=agent_id,
                    sub="phase3-demo@127.0.0.1",
                    cnf_jwk=cnf_jwk,
                    private_key=agent.private_key,
                    kid=agent.kid,
                )
                agp = parse_token_claims(sample_agent_jwt)["payload"]
                gdwk = agp.get("dwk")
                print(f"  Agent token (sample JWT) dwk: {gdwk or '(not present)'}", file=sys.stderr)
                print(
                    "    (Runtime requests use sig=jwks_uri; sample uses create_agent_token for dwk check.)",
                    file=sys.stderr,
                )
                if gdwk != "aauth-agent.json":
                    errs.append(f"agent token dwk: expected aauth-agent.json, got {gdwk!r}")

                if errs:
                    test2_error = "; ".join(errs)
                    for e in errs:
                        print(f"\n  ✗ {e}", file=sys.stderr)
                else:
                    test2_passed = True
                    print(f"\n  ✓ Resource token dwk = aauth-resource.json", file=sys.stderr)
                    print(f"  ✓ Auth token dwk = aauth-access.json", file=sys.stderr)
                    print(f"  ✓ Agent token dwk = aauth-agent.json", file=sys.stderr)

        except Exception as e:
            test2_error = str(e)
            print(f"\n✗ TEST 2 FAILED: {e}", file=sys.stderr, flush=True)
            traceback.print_exc()

        status = "✓ PASSED" if test2_passed else "✗ FAILED"
        print(f"\n{status}: TEST 2: Verify dwk Claims", file=sys.stderr)
        test_results.append(("TEST 2: Verify dwk Claims", test2_passed, test2_error))

        # =========================================================================
        # Summary
        # =========================================================================
        print("\n" + "=" * 80, file=sys.stderr)
        print("TEST SUMMARY", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        for test_name, passed, error in test_results:
            status = "✓ PASSED" if passed else "✗ FAILED"
            print(f"{status}: {test_name}", file=sys.stderr)
            if error:
                print(f"  Error: {error}", file=sys.stderr)

        total_tests = len(test_results)
        passed_tests = sum(1 for _, passed, _ in test_results if passed)
        failed_tests = total_tests - passed_tests

        print("\n" + "-" * 80, file=sys.stderr)
        print(f"Total: {total_tests} | Passed: {passed_tests} | Failed: {failed_tests}", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)

    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
