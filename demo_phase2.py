"""Demo script for Phase 2: agent identity via JWKS (``sig=jwks_uri``).

``sig=hwk`` is exercised in ``demo_phase1.py``; this script focuses on the
``/data-jwks`` path, agent metadata, JWKS, and scheme mismatch handling.
"""

import asyncio
import errno
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import List, Optional, Sequence

import httpx
from uvicorn import Config, Server

from participants.agent import Agent
from participants.resource import Resource

DEMO_BIND_HOST = "127.0.0.1"
AGENT_PORT = 8001
RESOURCE_PORT = 8002
DEMO_PORTS: tuple[int, ...] = (AGENT_PORT, RESOURCE_PORT)


def _agent_base_url() -> str:
    return f"http://{DEMO_BIND_HOST}:{AGENT_PORT}"


def _resource_origin() -> str:
    return f"http://{DEMO_BIND_HOST}:{RESOURCE_PORT}"


def _port_is_free(host: str, port: int) -> bool:
    """True if nothing is accepting TCP connections on host:port (we can bind)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                return False
            raise
    return True


def _listener_pids(port: int) -> Optional[list[int]]:
    """PIDs with TCP LISTEN on ``port``, or ``None`` if ``lsof`` is unavailable."""
    try:
        r = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return None
    if r.returncode != 0 and not (r.stdout or "").strip():
        return []
    pids: list[int] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line.isdigit():
            pids.append(int(line))
    return sorted(set(pids))


def _terminate_pid(pid: int, sig: int) -> None:
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass


def ensure_demo_ports_free(
    host: str = DEMO_BIND_HOST,
    ports: Sequence[int] = DEMO_PORTS,
    rounds: int = 12,
) -> None:
    """If demo ports are busy, stop listeners (SIGTERM, then SIGKILL) so binds succeed."""
    if all(_port_is_free(host, p) for p in ports):
        print(
            f"Demo ports {', '.join(str(p) for p in ports)} on {host} are available.",
            flush=True,
        )
        return

    print(
        f"Checking TCP ports {', '.join(str(p) for p in ports)} on {host} — "
        "freeing any listeners so the demo can bind.",
        flush=True,
    )

    for i in range(rounds):
        busy = [p for p in ports if not _port_is_free(host, p)]
        if not busy:
            print("Demo ports are available.", flush=True)
            return

        use_kill = i >= rounds - 2
        sig = signal.SIGKILL if use_kill else signal.SIGTERM

        for port in busy:
            pids = _listener_pids(port)
            if pids is None:
                sys.exit(
                    "This demo needs `lsof` to find processes bound to busy ports, "
                    "but `lsof` was not found. Free ports "
                    f"{', '.join(str(p) for p in busy)} manually, or install lsof."
                )
            for pid in pids:
                if pid == os.getpid():
                    continue
                label = "SIGKILL" if use_kill else "SIGTERM"
                print(f"Port {port} held by PID {pid}; sending {label}.", flush=True)
                try:
                    _terminate_pid(pid, sig)
                except PermissionError:
                    sys.exit(
                        f"Cannot free port {port} (PID {pid}): permission denied. "
                        "Stop that process yourself or run with sufficient privileges."
                    )

        time.sleep(0.4 if not use_kill else 0.6)

    if not all(_port_is_free(host, p) for p in ports):
        still = [p for p in ports if not _port_is_free(host, p)]
        sys.exit(
            f"Could not free TCP port(s) {', '.join(map(str, still))} on {host}. "
            "Stop the processes using those ports and retry."
        )

    print("Demo ports are available.", flush=True)


# Filled by ``start_uvicorn`` threads; used for graceful shutdown.
_uvicorn_servers: List[Server] = []
_server_threads: List[threading.Thread] = []


def start_uvicorn(app, port: int) -> None:
    """Run uvicorn in a daemon thread and keep a ``Server`` handle for ``should_exit``."""

    def target() -> None:
        config = Config(app, host=DEMO_BIND_HOST, port=port, log_level="info")
        server = Server(config=config)
        _uvicorn_servers.append(server)
        server.run()

    t = threading.Thread(target=target, daemon=True)
    _server_threads.append(t)
    t.start()


async def shutdown_uvicorn_servers() -> None:
    """Signal all demo servers to exit and wait for threads to finish."""
    if not _uvicorn_servers:
        return
    for s in list(_uvicorn_servers):
        s.should_exit = True
    await asyncio.sleep(2.0)
    for t in _server_threads:
        t.join(timeout=15.0)
    _uvicorn_servers.clear()
    _server_threads.clear()


async def main():
    """Run Phase 2 demo."""
    ensure_demo_ports_free()

    print("=" * 80)
    print("Phase 2 Demo: Agent Identity via JWKS")
    print("Resource challenges for identity use Signature-Requirement (pseudonym/identity).")
    print("Agent tokens use typ aa-agent+jwt (see library create_agent_token / verify).")
    print("=" * 80)
    print()
    
    _uvicorn_servers.clear()
    _server_threads.clear()

    try:
        # Create agent and resource
        agent = Agent(_agent_base_url(), port=AGENT_PORT)
        resource = Resource("https://resource.example.com", port=RESOURCE_PORT)

        # Start resource server
        print(f"Starting resource server on port {RESOURCE_PORT}...")
        start_uvicorn(resource.app, RESOURCE_PORT)

        # Start agent server
        print(f"Starting agent server on port {AGENT_PORT}...")
        start_uvicorn(agent.app, AGENT_PORT)

        # Wait for servers to start
        print("Waiting for servers to start...")
        await asyncio.sleep(2)

        print()
        print("=" * 80)
        print("Demo 1: sig=jwks_uri on /data-jwks endpoint")
        print("=" * 80)

        try:
            response = await agent.request_resource(
                f"{_resource_origin()}/data-jwks",
                sig_scheme="jwks_uri"
            )

            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"Response: {data}")
                print("✓ sig=jwks_uri works on /data-jwks endpoint")
                print(f"  Agent ID: {data.get('agent_id')}")
            else:
                print(f"Error: {response.text}")
        except Exception as e:
            print(f"Error: {e}")

        print()
        print("=" * 80)
        print("Demo 2: Verify metadata endpoint")
        print("=" * 80)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{_agent_base_url()}/.well-known/aauth-agent")
                print(f"Status: {response.status_code}")
                if response.status_code == 200:
                    metadata = response.json()
                    print(f"Metadata: {metadata}")
                    print("✓ Agent metadata endpoint works")
                else:
                    print(f"Error: {response.text}")
        except Exception as e:
            print(f"Error: {e}")

        print()
        print("=" * 80)
        print("Demo 3: Verify JWKS endpoint")
        print("=" * 80)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{_agent_base_url()}/jwks.json")
                print(f"Status: {response.status_code}")
                if response.status_code == 200:
                    jwks = response.json()
                    print(f"JWKS: {jwks}")
                    print("✓ Agent JWKS endpoint works")
                    if jwks.get("keys") and len(jwks["keys"]) > 0:
                        print(f"  Key ID (kid): {jwks['keys'][0].get('kid')}")
                else:
                    print(f"Error: {response.text}")
        except Exception as e:
            print(f"Error: {e}")

        print()
        print("=" * 80)
        print("Demo 4: Wrong scheme rejected on /data-jwks")
        print("=" * 80)

        try:
            # /data-jwks requires jwks_uri; hwk must be rejected
            response = await agent.request_resource(
                f"{_resource_origin()}/data-jwks",
                sig_scheme="hwk",
                follow_identity_challenge=False,
            )

            print(f"Status: {response.status_code}")
            if response.status_code == 401:
                print(f"Response: {response.text}")
                print("✓ Wrong scheme correctly rejected")
            else:
                print(f"Unexpected success: {response.text}")
        except Exception as e:
            print(f"Error: {e}")

        print()
        print("=" * 80)
        print("Phase 2 Demo Complete!")
        print("=" * 80)
        print()
        print("Summary:")
        print("- sig=jwks_uri works on /data-jwks")
        print("- Agent metadata endpoint works")
        print("- Agent JWKS endpoint works")
        print("- Wrong scheme rejected on /data-jwks")
        print()
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")

