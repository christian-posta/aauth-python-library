"""pytest configuration for AAuth tests.

Provides server lifecycle management to prevent port conflicts between tests.
Tests that start uvicorn servers in daemon threads leave those servers running
across tests, causing port-already-in-use errors. This conftest patches
uvicorn.run() to track server instances and stops them after each test.
"""

import socket
import time
import pytest
import uvicorn

_active_servers: list = []
_orig_uvicorn_run = uvicorn.run


def _patched_uvicorn_run(app, **kwargs):
    """Tracked replacement for uvicorn.run() that enables post-test cleanup."""
    host = kwargs.get("host", "127.0.0.1")
    port = kwargs.get("port", 8000)
    log_level = kwargs.get("log_level", "error")
    config = uvicorn.Config(app, host=host, port=port, log_level=log_level)
    server = uvicorn.Server(config)
    _active_servers.append((host, port, server))
    server.run()


# Patch at import time so daemon threads inherit the patched version
uvicorn.run = _patched_uvicorn_run


def _is_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if nothing is actively listening on port.

    Uses TCP connect rather than bind() to avoid SO_REUSEADDR false-positives on macOS.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            result = s.connect_ex((host, port))
            # 0 means connection succeeded → something is listening → port NOT free
            return result != 0
    except OSError:
        return True


@pytest.fixture(autouse=True)
def _server_lifecycle():
    """Stop all servers that were started during a test before the next test begins."""
    snapshot = list(_active_servers)
    yield
    # Find servers started during this test
    new_entries = [e for e in _active_servers if e not in snapshot]
    if not new_entries:
        return

    # Signal each server to stop
    for _host, _port, server in new_entries:
        try:
            server.should_exit = True
        except Exception:
            pass

    # Give uvicorn's event loop time to process the shutdown signal
    time.sleep(0.5)

    # Poll until all ports are free (up to 4.5 more seconds)
    ports = [p for _, p, _ in new_entries]
    deadline = time.monotonic() + 4.5
    while time.monotonic() < deadline:
        if all(_is_port_free(p) for p in ports):
            break
        time.sleep(0.1)

    # Remove tracked entries
    for entry in new_entries:
        try:
            _active_servers.remove(entry)
        except ValueError:
            pass
