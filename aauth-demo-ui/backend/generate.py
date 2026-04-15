#!/usr/bin/env python3
"""
AAuth Demo UI — Scenario Data Generator

Generates realistic JSON fixtures using the actual aauth library.
Real Ed25519 key pairs, real JWTs, real HTTP Message Signatures.

Usage:
    uv run python generate.py
    uv run python generate.py --scenario pseudonymous
"""

import sys
import os
import json
import base64
import hashlib
import argparse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aauth import (
    generate_ed25519_keypair,
    public_key_to_jwk,
    calculate_jwk_thumbprint,
    create_agent_token,
    create_resource_token,
    create_auth_token,
    parse_token_claims,
)

OUTPUT_DIR = Path(__file__).parent.parent / "frontend" / "lib" / "scenarios"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fake_sig(seed: int = 0) -> str:
    """Return a realistic-looking (but fake) base64url Ed25519 signature."""
    data = bytes([seed % 256]) * 64
    return b64url(data)


def decode_jwt_parts(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    def dec(p: str) -> dict:
        pad = "=" * (4 - len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p + pad))
    return dec(parts[0]), dec(parts[1]), parts[2]


def token_fixture(name: str, token: str) -> dict:
    header, payload, sig = decode_jwt_parts(token)
    return {"name": name, "typ": header.get("typ", "unknown"),
            "raw": token, "header": header, "payload": payload, "signature_b64": sig}


def jwks_uri_sig_key(agent_id: str, kid: str) -> str:
    return f'sig=jwks_uri;id="{agent_id}";kid="{kid}"'


def hwk_sig_key(jwk: dict) -> str:
    return f"sig=hwk;jwk={json.dumps(jwk, separators=(',', ':'))}"


def sig_headers(sig_key: str, sig_input: str, seed: int = 0) -> dict:
    return {
        "Signature-Key": sig_key,
        "Signature-Input": f"sig={sig_input}",
        "Signature": f"sig=:{fake_sig(seed)}:",
    }


def standard_sig_input(components: list[str] | None = None) -> str:
    comps = components or ["@method", "@authority", "@path", "signature-key"]
    comp_str = " ".join(f'"{c}"' for c in comps)
    return f'({comp_str});created=1700000000;alg="ed25519"'


def write_scenario(scenario_id: str, data: dict) -> None:
    path = OUTPUT_DIR / f"{scenario_id}.json"
    path.write_text(json.dumps(data, indent=2))
    print(f"  ✓  {scenario_id}.json")


def sha256_b64url(data: bytes) -> str:
    return b64url(hashlib.sha256(data).digest())


# ─── Keys factory ─────────────────────────────────────────────────────────────

def make_keypair(kid: str) -> tuple:
    priv, pub = generate_ed25519_keypair()
    jwk = public_key_to_jwk(pub, kid=kid)
    jkt = calculate_jwk_thumbprint(jwk)
    return priv, pub, jwk, jkt


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNING SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_pseudonymous() -> None:
    print("Generating: pseudonymous (Phase 1)")
    _, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")

    resource_id = "http://127.0.0.1:8002"
    authority = "127.0.0.1:8002"
    sig_key = hwk_sig_key(agent_jwk)
    sig_input = standard_sig_input()
    sig_base = (
        '"@method": GET\n'
        f'"@authority": {authority}\n'
        '"@path": /data\n'
        f'"signature-key": {sig_key}\n'
        f'"@signature-params": {sig_input}'
    )

    scenario = {
        "id": "pseudonymous",
        "title": "Pseudonymous Signing (sig=hwk)",
        "description": (
            "The agent proves possession of a key without revealing its identity. "
            "The Ed25519 public key is embedded inline in the Signature-Key header (hwk). "
            "The resource verifies the signature but learns nothing about who the agent is."
        ),
        "spec_section": "§ HTTP Message Signatures — Pseudonymous",
        "category": "signing",
        "demo_phase": 1,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Unsigned GET /data → 401",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {"Host": authority, "Accept": "application/json"},
                "request_body": None,
                "response_status": 401,
                "response_headers": {
                    "Accept-Signature": 'sig=("@method" "@authority" "@path" "signature-key");sigkey=jkt',
                    "WWW-Authenticate": "AAuth",
                    "Content-Type": "application/json",
                },
                "response_body": {"error": "signature_required", "message": "Request must be signed"},
                "tokens": [], "signature": None,
                "annotations": [
                    "Resource returns 401 + Accept-Signature challenge.",
                    "sigkey=jkt tells the agent: include your public key JWK thumbprint in Signature-Key.",
                    "Covered components (@method, @authority, @path, signature-key) must all be signed.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "resource",
                "label": "Signed GET (sig=hwk) → 200",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    "Host": authority, "Accept": "application/json",
                    **sig_headers(sig_key, sig_input, seed=1),
                },
                "request_body": None,
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "message": "Hello, pseudonymous agent!",
                    "note": "Agent verified by key possession — identity unknown to resource",
                },
                "tokens": [],
                "signature": {
                    "scheme": "hwk",
                    "signature_base": sig_base,
                    "signature_input": f"sig={sig_input}",
                    "signature_key": sig_key,
                    "covered_components": ["@method", "@authority", "@path", "signature-key"],
                },
                "annotations": [
                    "Agent embeds its Ed25519 public key inline in Signature-Key (hwk = inline key).",
                    "No agent identifier is disclosed — pseudonymous: resource sees 'a key', not 'an agent'.",
                    "Resource verifies the signature against the inline JWK and grants access.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("pseudonymous", scenario)


def generate_identity() -> None:
    print("Generating: identity (Phase 2)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    authority = "127.0.0.1:8002"
    kid = "agent-key-1"

    agent_token = create_agent_token(
        iss=agent_id, sub="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=agent_priv, kid=kid,
    )
    agent_metadata = {
        "id": agent_id,
        "jwks_uri": f"{agent_id}/jwks.json",
        "signing_alg_values_supported": ["ed25519"],
        "token_endpoint": f"{agent_id}/token",
    }

    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()
    sig_base = (
        '"@method": GET\n'
        f'"@authority": {authority}\n'
        '"@path": /data-jwks\n'
        f'"signature-key": {sig_key}\n'
        f'"@signature-params": {sig_input}'
    )

    scenario = {
        "id": "identity",
        "title": "Agent Identity via JWKS (sig=jwks_uri)",
        "description": (
            "The agent signs requests and includes its identifier URI + key ID in Signature-Key. "
            "The resource fetches the agent's JWKS from its well-known endpoint to verify the signature, "
            "establishing cryptographic identity — the resource learns who the agent is."
        ),
        "spec_section": "§ Agent Identity",
        "category": "signing",
        "demo_phase": 2,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001,
             "metadata_url": f"{agent_id}/.well-known/aauth-agent",
             "jwks_url": f"{agent_id}/jwks.json"},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Unsigned GET /data-jwks → 401",
                "method": "GET", "url": f"{resource_id}/data-jwks",
                "request_headers": {"Host": authority},
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "Accept-Signature": 'sig=("@method" "@authority" "@path" "signature-key");sigkey=uri',
                    "WWW-Authenticate": "AAuth",
                },
                "response_body": {"error": "signature_required"},
                "tokens": [], "signature": None,
                "annotations": [
                    "sigkey=uri challenge: include your agent identifier URI in Signature-Key.",
                    "This enables the resource to fetch your JWKS and discover your identity.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "resource",
                "label": "Signed GET (sig=jwks_uri) → resource fetches JWKS",
                "method": "GET", "url": f"{resource_id}/data-jwks",
                "request_headers": {
                    "Host": authority,
                    **sig_headers(sig_key, sig_input, seed=2),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"message": f"Hello, {agent_id}!", "verified_jkt": agent_jkt},
                "tokens": [token_fixture("Agent Token", agent_token)],
                "signature": {
                    "scheme": "jwks_uri",
                    "signature_base": sig_base,
                    "signature_input": f"sig={sig_input}",
                    "signature_key": sig_key,
                    "covered_components": ["@method", "@authority", "@path", "signature-key"],
                },
                "annotations": [
                    f"Signature-Key contains id=\"{agent_id}\" and kid=\"{kid}\".",
                    "Resource resolves /.well-known/aauth-agent on the agent's host to find jwks_uri.",
                    "Resource fetches JWKS, matches key by kid, verifies signature.",
                    "Unlike hwk: resource now knows the full agent identifier — identity, not pseudonymity.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "resource", "to": "agent",
                "label": "Fetch /.well-known/aauth-agent",
                "method": "GET", "url": f"{agent_id}/.well-known/aauth-agent",
                "request_headers": {"Host": "127.0.0.1:8001"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": agent_metadata,
                "tokens": [], "signature": None,
                "annotations": [
                    "Resource discovers the agent's metadata from the id in Signature-Key.",
                    "Metadata contains jwks_uri — where public keys are published.",
                ],
                "is_response": True,
            },
            {
                "step": 4, "from": "resource", "to": "agent",
                "label": "Fetch /jwks.json → verify signature",
                "method": "GET", "url": f"{agent_id}/jwks.json",
                "request_headers": {"Host": "127.0.0.1:8001"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"keys": [agent_jwk]},
                "tokens": [], "signature": None,
                "annotations": [
                    f"Resource matches key by kid=\"{kid}\" and verifies the HTTP Message Signature.",
                    f"JKT = {agent_jkt[:24]}… (SHA-256 thumbprint of the public key JWK).",
                ],
                "is_response": True,
            },
        ],
    }
    write_scenario("identity", scenario)


# ═══════════════════════════════════════════════════════════════════════════════
# RESOURCE ACCESS SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_federated() -> None:
    print("Generating: federated (Phase 3 — 4-party autonomous)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    as_priv, _, _, _ = make_keypair("as-key-1")
    ps_priv, _, _, _ = make_keypair("ps-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"

    agent_token = create_agent_token(
        iss=agent_id, sub="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=agent_priv, kid=kid, ps=ps_id,
    )
    resource_token = create_resource_token(
        iss=resource_id, aud=as_id, agent=agent_id, agent_jkt=agent_jkt,
        scope="read", private_key=as_priv, kid="as-key-1",
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id, agent="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as_priv, kid="as-key-1", scope="read",
        act={"sub": agent_id},
    )

    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()

    scenario = {
        "id": "federated",
        "title": "Federated / Autonomous Authorization (4-party)",
        "description": (
            "The complete 4-party autonomous flow: Agent → Resource → Person Server → Access Server. "
            "No user interaction. The PS federates to the AS on behalf of the agent, "
            "and the AS issues an aa-auth+jwt that the agent presents to the resource."
        ),
        "spec_section": "§ PS-AS Federation",
        "category": "access",
        "demo_phase": 3,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
        ],
        "token_flow": [
            {
                "token": "resource-token",
                "label": "Resource Token",
                "tokenType": "aa-resource+jwt",
                "accent": "resource",
                "events": [
                    {"step": 1, "participant": "resource", "label": "Issued in 401 challenge", "kind": "issued"},
                    {"step": 2, "participant": "agent", "label": "Forwarded to the PS", "kind": "forwarded"},
                    {"step": 3, "participant": "ps", "label": "Presented to the AS", "kind": "presented"},
                ],
            },
            {
                "token": "auth-token",
                "label": "Auth Token",
                "tokenType": "aa-auth+jwt",
                "accent": "auth",
                "events": [
                    {"step": 3, "participant": "as", "label": "Minted after federation", "kind": "issued"},
                    {"step": 4, "participant": "ps", "label": "Returned to the agent", "kind": "returned"},
                    {"step": 5, "participant": "agent", "label": "Presented to the resource", "kind": "presented"},
                ],
            },
            {
                "token": "agent-token",
                "label": "Agent Token",
                "tokenType": "aa-agent+jwt",
                "accent": "agent",
                "events": [
                    {"step": 3, "participant": "ps", "label": "Used to prove the agent's PS binding", "kind": "presented"},
                ],
            },
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Signed GET /data-auth → 401 + resource token",
                "method": "GET", "url": f"{resource_id}/data-auth",
                "request_headers": {"Host": "127.0.0.1:8002", **sig_headers(sig_key, sig_input, 10)},
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{resource_token[:48]}…"',
                    "Content-Type": "application/json",
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": {
                    "scheme": "jwks_uri",
                    "signature_base": (
                        '"@method": GET\n"@authority": 127.0.0.1:8002\n"@path": /data-auth\n'
                        f'"signature-key": {sig_key}\n"@signature-params": {sig_input}'
                    ),
                    "signature_input": f"sig={sig_input}",
                    "signature_key": sig_key,
                    "covered_components": ["@method", "@authority", "@path", "signature-key"],
                },
                "annotations": [
                    "Agent signs with sig=jwks_uri (agent identity).",
                    "Resource issues 401 + AAuth-Requirement containing aa-resource+jwt.",
                    "Resource token has aud=AS — only the AS can honour it.",
                    "The agent token's ps claim tells the ecosystem which Person Server represents this agent.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "ps",
                "label": "POST resource token to PS /token",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(sig_key, sig_input, 11),
                },
                "request_body": {"resource_token": resource_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"status": "accepted", "next": "ps_federates_to_as"},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Agent sends the resource token to its Person Server (discovered from agent's ps claim).",
                    "PS discovers the AS from the resource token's aud claim.",
                    "The PS does not mint the auth token itself in this mode; it federates to the AS next.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "ps", "to": "as",
                "label": "PS federates to AS /token",
                "method": "POST", "url": f"{as_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(jwks_uri_sig_key(ps_id, "ps-key-1"), sig_input, 12),
                },
                "request_body": {"resource_token": resource_token, "agent_token": agent_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Agent Token", agent_token), token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "PS signs with its own identity (sig=jwks_uri with PS identifier).",
                    "AS verifies PS is in its trusted_person_servers list.",
                    "AS verifies agent_jkt in resource token matches agent token cnf.jwk thumbprint.",
                    "Auth token: iss=AS, aud=resource, agent=aauth:local@127.0.0.1, cnf.jwk=agent key, act.sub=agent URI.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "as", "to": "ps",
                "label": "AS returns auth token → PS → Agent",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {"auth_token": auth_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "The AS sends the aa-auth+jwt back to the Person Server.",
                    "The PS returns the same auth token to the agent without altering it.",
                    "This keeps token issuance at the AS while the PS remains the federation intermediary.",
                ],
                "is_response": True,
            },
            {
                "step": 5, "from": "agent", "to": "resource",
                "label": "Retry with auth token → 200",
                "method": "GET", "url": f"{resource_id}/data-auth",
                "request_headers": {
                    "Host": "127.0.0.1:8002",
                    "AAuth-Access": f"token={auth_token[:40]}…",
                    **sig_headers(sig_key, sig_input, 13),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"message": "Access granted!", "agent": "aauth:local@127.0.0.1", "scope": "read"},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "Agent presents auth token via AAuth-Access header.",
                    "Resource verifies: signature valid, aud=this resource, not expired.",
                    "Resource extracts agent identity, scope, and act chain from the token payload.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("federated", scenario)


def generate_user_delegation() -> None:
    print("Generating: user-delegation (Phase 4)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    as_priv, _, _, _ = make_keypair("as-key-1")
    make_keypair("ps-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"

    resource_token = create_resource_token(
        iss=resource_id, aud=as_id, agent=agent_id, agent_jkt=agent_jkt,
        scope="read write", private_key=as_priv, kid="as-key-1",
    )
    agent_token = create_agent_token(
        iss=agent_id, sub="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=agent_priv, kid=kid, ps=ps_id,
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id, agent="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as_priv, kid="as-key-1", scope="read write",
        act={"sub": agent_id},
    )

    interaction_code = "a3f8c2d1e94b7065"
    pending_url = f"{as_id}/pending/{interaction_code}"
    interact_url = f"{as_id}/interact?code={interaction_code}"
    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()

    scenario = {
        "id": "user-delegation",
        "title": "User Delegation — Deferred Authorization",
        "description": (
            "The Access Server requires user consent before issuing an auth token. "
            "It returns 202 Accepted with a pending URL (for polling) and an interaction URL "
            "(for the user to visit). Agent polls while user approves in a browser."
        ),
        "spec_section": "§ User Delegation",
        "category": "access",
        "demo_phase": 4,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
            {"id": "user", "label": "User", "type": "user"},
        ],
        "token_flow": [
            {
                "token": "resource-token",
                "label": "Resource Token",
                "tokenType": "aa-resource+jwt",
                "accent": "resource",
                "events": [
                    {"step": 1, "participant": "resource", "label": "Issued in 401 challenge", "kind": "issued"},
                    {"step": 2, "participant": "agent", "label": "Forwarded to the PS", "kind": "forwarded"},
                    {"step": 3, "participant": "ps", "label": "Presented to the AS", "kind": "presented"},
                ],
            },
            {
                "token": "agent-token",
                "label": "Agent Token",
                "tokenType": "aa-agent+jwt",
                "accent": "agent",
                "events": [
                    {"step": 3, "participant": "ps", "label": "Used to prove the agent's PS binding", "kind": "presented"},
                ],
            },
            {
                "token": "auth-token",
                "label": "Auth Token",
                "tokenType": "aa-auth+jwt",
                "accent": "auth",
                "events": [
                    {"step": 7, "participant": "as", "label": "Released after user approval", "kind": "issued"},
                    {"step": 8, "participant": "agent", "label": "Presented to the resource", "kind": "presented"},
                ],
            },
        ],
        "deferred_timeline": {
            "title": "Deferred Authorization Polling",
            "events": [
                {"step": 4, "status": 202, "label": "Initial deferred response", "detail": "AS returns pending and interaction URLs."},
                {"step": 5, "status": 202, "label": "First poll", "detail": "User has not approved yet; keep polling the pending URL."},
                {"step": 7, "status": 200, "label": "Approved", "detail": "After consent, the next poll returns the auth token."},
            ],
        },
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "GET /data-auth → 401 + resource token",
                "method": "GET", "url": f"{resource_id}/data-auth",
                "request_headers": {"Host": "127.0.0.1:8002", **sig_headers(sig_key, sig_input, 20)},
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{resource_token[:48]}…"',
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": {
                    "scheme": "jwks_uri",
                    "signature_base": (
                        '"@method": GET\n"@authority": 127.0.0.1:8002\n"@path": /data-auth\n'
                        f'"signature-key": {sig_key}\n"@signature-params": {sig_input}'
                    ),
                    "signature_input": f"sig={sig_input}",
                    "signature_key": sig_key,
                    "covered_components": ["@method", "@authority", "@path", "signature-key"],
                },
                "annotations": [
                    "Resource issues 401 + resource token challenge.",
                    "The flow starts like Phase 3, but the AS will defer issuance pending user consent.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "ps",
                "label": "POST resource token to PS",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {"Content-Type": "application/json", **sig_headers(sig_key, sig_input, 21)},
                "request_body": {"resource_token": resource_token},
                "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "status": "ps_forwarding_to_as",
                },
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Agent hands the resource token to its Person Server.",
                    "The PS will federate to the AS on the agent's behalf in the next step.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "ps", "to": "as",
                "label": "PS federates to AS /token",
                "method": "POST", "url": f"{as_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(jwks_uri_sig_key(ps_id, "ps-key-1"), sig_input, 22),
                },
                "request_body": {"resource_token": resource_token, "agent_token": agent_token},
                "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "pending": pending_url,
                    "interaction": interact_url,
                    "expires_in": 600,
                },
                "tokens": [
                    token_fixture("Resource Token", resource_token),
                    token_fixture("Agent Token", agent_token),
                ],
                "signature": None,
                "annotations": [
                    "PS signs with its own jwks_uri identity while calling the AS token endpoint.",
                    "AS validates the trusted PS, inspects the resource token, and defers the decision.",
                    "Instead of minting an auth token immediately, the AS returns 202 + pending URL + interaction URL.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "as", "to": "ps",
                "label": "AS returns 202 → PS → Agent",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {
                    "pending": pending_url,
                    "interaction": interact_url,
                    "expires_in": 600,
                },
                "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "pending": pending_url,
                    "interaction": interact_url,
                    "expires_in": 600,
                },
                "tokens": [],
                "signature": None,
                "annotations": [
                    "The PS propagates the deferred response back to the agent unchanged.",
                    "This is the body the UI needs to highlight: {pending, interaction, expires_in}.",
                    f"pending: {pending_url}",
                    f"interaction: {interact_url}",
                ],
                "is_response": False,
            },
            {
                "step": 5, "from": "agent", "to": "ps",
                "label": "Poll pending URL → 202 still pending",
                "method": "GET", "url": pending_url,
                "request_headers": {**sig_headers(sig_key, sig_input, 23)},
                "request_body": None, "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "pending": pending_url,
                    "status": "waiting_for_user",
                },
                "tokens": [],
                "signature": None,
                "annotations": [
                    "The agent can poll immediately, but the request is still waiting on user consent.",
                    "This gives the second 202 in the 202 → 202 → 200 progression.",
                ],
                "is_response": False,
            },
            {
                "step": 6, "from": "user", "to": "as",
                "label": "User opens interaction URL → grants consent",
                "method": "GET", "url": interact_url,
                "request_headers": {"Cookie": "session=abc123"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "text/html"},
                "response_body": (
                    "<div class=\"consent-page\">"
                    "<h1>Approve Agent Access</h1>"
                    "<p>Agent: http://127.0.0.1:8001</p>"
                    "<p>Resource: http://127.0.0.1:8002/data-auth</p>"
                    "<p>Scope: read write</p>"
                    "<button>Approve</button>"
                    "</div>"
                ),
                "tokens": [],
                "signature": None,
                "annotations": [
                    "AS renders a consent page summarizing the requesting agent, resource, and scope.",
                    "The user authenticates and approves the request in the browser.",
                    "Once approved, the pending request transitions to a token-ready state.",
                ],
                "is_response": False,
            },
            {
                "step": 7, "from": "agent", "to": "ps",
                "label": "Poll pending URL → 200 + auth token",
                "method": "GET", "url": pending_url,
                "request_headers": {**sig_headers(sig_key, sig_input, 24)},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "After approval, the next poll returns 200 with the AS-issued auth token.",
                    "The auth token still binds the agent key via cnf.jwk and records act.sub as the requesting agent.",
                ],
                "is_response": False,
            },
            {
                "step": 8, "from": "agent", "to": "resource",
                "label": "Retry with auth token → 200",
                "method": "GET", "url": f"{resource_id}/data-auth",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token[:40]}…",
                    **sig_headers(sig_key, sig_input, 25),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"message": "Access granted!", "scope": "read write"},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "Resource verifies the AS-issued auth token and the agent's bound signature.",
                    "The resulting access now reflects user-delegated scope rather than autonomous approval.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("user-delegation", scenario)


def generate_ps_managed() -> None:
    print("Generating: ps-managed (Phase 11 — PS-AS federation trust)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    as_priv, _, as_jwk, _ = make_keypair("as-key-1")
    ps_priv, _, ps_jwk, _ = make_keypair("ps-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"

    agent_token = create_agent_token(
        iss=agent_id, sub="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=agent_priv, kid=kid, ps=ps_id,
    )
    resource_token = create_resource_token(
        iss=resource_id, aud=as_id, agent=agent_id, agent_jkt=agent_jkt,
        scope="read", private_key=as_priv, kid="as-key-1",
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id, agent="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as_priv, kid="as-key-1", scope="read",
    )
    ps_metadata = {
        "person_server": ps_id,
        "token_endpoint": f"{ps_id}/token",
        "mission_endpoint": f"{ps_id}/mission",
        "jwks_uri": f"{ps_id}/jwks.json",
    }

    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()

    scenario = {
        "id": "ps-managed",
        "title": "PS–AS Federation Trust (Normative 4-party Path)",
        "description": (
            "The spec-normative flow: agent's token includes a ps claim identifying its Person Server. "
            "The resource token has aud=AS. The PS is the ONLY entity that calls the AS token endpoint — "
            "it federates using its own identity. The AS trusts the PS via trusted_person_servers configuration."
        ),
        "spec_section": "§ PS-AS Federation Trust",
        "category": "access",
        "demo_phase": 11,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Request with agent token (ps claim) → 401",
                "method": "GET", "url": f"{resource_id}/data-auth",
                "request_headers": {"Host": "127.0.0.1:8002", **sig_headers(sig_key, sig_input, 30)},
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{resource_token[:48]}…"',
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("Agent Token", agent_token), token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Agent token contains ps claim: ps=\"http://127.0.0.1:8004\".",
                    "Resource discovers the agent's PS from the agent token's ps claim.",
                    "Resource token: aud=AS (not PS) — the PS must forward to the AS.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "resource", "to": "ps",
                "label": "Resource discovers PS metadata",
                "method": "GET", "url": f"{ps_id}/.well-known/aauth-person.json",
                "request_headers": {"Host": "127.0.0.1:8004"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": ps_metadata,
                "tokens": [], "signature": None,
                "annotations": [
                    "Resource fetches PS well-known metadata to find the token_endpoint.",
                    "This discovery is driven by the ps claim in the agent token.",
                ],
                "is_response": True,
            },
            {
                "step": 3, "from": "agent", "to": "ps",
                "label": "Agent sends resource token to PS /token",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(sig_key, sig_input, 31),
                },
                "request_body": {"resource_token": resource_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Agent sends resource token to PS (discovered from agent token's ps claim).",
                    "PS inspects resource token: aud=AS — must federate.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "ps", "to": "as",
                "label": "PS federates to AS (signs with PS identity)",
                "method": "POST", "url": f"{as_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(jwks_uri_sig_key(ps_id, "ps-key-1"), sig_input, 32),
                },
                "request_body": {"resource_token": resource_token, "agent_token": agent_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Agent Token", agent_token), token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "KEY POINT: PS calls AS, not the agent. PS signs with its own jwks_uri identity.",
                    "AS checks: is this PS in trusted_person_servers? Yes → proceed.",
                    "AS verifies agent_jkt matches cnf.jwk thumbprint in agent token.",
                    "AS issues auth token: iss=AS, aud=resource, agent=aauth:local@127.0.0.1.",
                ],
                "is_response": False,
            },
            {
                "step": 5, "from": "agent", "to": "resource",
                "label": "Present auth token → 200",
                "method": "GET", "url": f"{resource_id}/data-auth",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token[:40]}…",
                    **sig_headers(sig_key, sig_input, 33),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"message": "Access granted!", "agent": "aauth:local@127.0.0.1"},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": ["Resource verifies auth token — iss=trusted AS, aud=this resource."],
                "is_response": False,
            },
        ],
    }
    write_scenario("ps-managed", scenario)


# ═══════════════════════════════════════════════════════════════════════════════
# MISSIONS SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

def _mission_blob_and_s256() -> tuple[dict, str]:
    mission_blob = {
        "description": "# Analyze Q2 Customer Feedback\n\nRead customer feedback records and produce a summary report with sentiment analysis and key themes.",
        "tools": [
            {"name": "FeedbackReader", "description": "Read customer feedback records"},
            {"name": "ReportWriter", "description": "Write the summary report to the shared drive"},
        ],
    }
    blob_bytes = json.dumps(mission_blob, separators=(",", ":")).encode()
    s256 = sha256_b64url(blob_bytes)
    return mission_blob, s256


def generate_missions_lifecycle() -> None:
    print("Generating: missions-lifecycle (Phase 5)")
    agent_priv, _, agent_jwk, _ = make_keypair("agent-key-1")
    ps_priv, _, ps_jwk, _ = make_keypair("ps-key-1")

    agent_id = "http://127.0.0.1:8001"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"

    mission_blob, s256 = _mission_blob_and_s256()
    ps_metadata = {
        "person_server": ps_id,
        "token_endpoint": f"{ps_id}/token",
        "mission_endpoint": f"{ps_id}/mission",
        "jwks_uri": f"{ps_id}/jwks.json",
    }
    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input(["@method", "@authority", "@path", "content-digest", "signature-key"])

    scenario = {
        "id": "missions-lifecycle",
        "title": "Mission Proposal & Approval",
        "description": (
            "The agent proposes a mission to the Person Server: a markdown description of what it intends "
            "to accomplish, plus a list of tools it will use. The PS approves and returns an AAuth-Mission "
            "header containing the approver URL and an s256 (SHA-256 hash of the mission blob)."
        ),
        "spec_section": "§ Missions",
        "category": "missions",
        "demo_phase": 5,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
        ],
        "mission_blob": {
            "title": "Approved Mission Blob",
            "description": "Mission proposal approved by the Person Server.",
            "markdown": mission_blob["description"],
            "tools": mission_blob["tools"],
            "approver": ps_id,
            "s256": s256,
            "capabilities": ["clarification", "interaction", "tool-approval"],
        },
        "s256_chain": [
            {
                "label": "Mission Proposal Body",
                "source": "POST /mission body",
                "s256": s256,
                "detail": "The agent computes the canonical mission blob bytes that will be approved.",
            },
            {
                "label": "AAuth-Mission Header",
                "source": "PS response header",
                "s256": s256,
                "detail": "The PS returns approver and s256 so later requests can reference the exact mission blob.",
            },
            {
                "label": "Client Verification",
                "source": "local hash check",
                "s256": s256,
                "detail": "The agent recomputes SHA-256 over the returned blob bytes and confirms the value matches.",
            },
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "ps",
                "label": "Discover PS metadata",
                "method": "GET", "url": f"{ps_id}/.well-known/aauth-person.json",
                "request_headers": {"Host": "127.0.0.1:8004"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": ps_metadata,
                "tokens": [], "signature": None,
                "annotations": [
                    "Agent discovers the PS's mission_endpoint from well-known metadata.",
                    "mission_endpoint is where the agent POSTs mission proposals.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "ps",
                "label": "POST mission proposal to /mission",
                "method": "POST", "url": f"{ps_id}/mission",
                "request_headers": {
                    "Content-Type": "application/json",
                    "AAuth-Capabilities": "clarification, interaction",
                    **sig_headers(sig_key, sig_input, 40),
                },
                "request_body": mission_blob,
                "response_status": 200,
                "response_headers": {
                    "Content-Type": "application/json",
                    "AAuth-Mission": f'approver="{ps_id}"; s256="{s256}"',
                    "AAuth-Capabilities": "clarification, interaction, tool-approval",
                },
                "response_body": mission_blob,
                "tokens": [], "signature": None,
                "annotations": [
                    "Agent sends mission description (Markdown) + tool list.",
                    "PS approves and responds with body = mission blob + AAuth-Mission header.",
                    f"s256 = SHA-256(blob_bytes) = {s256[:24]}…",
                    "Agent must store this s256 and present it in future requests as AAuth-Mission.",
                    "Request AAuth-Capabilities advertises agent support; response capabilities reflect the PS-approved set.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "agent", "to": "ps",
                "label": "Verify s256 matches blob",
                "method": "GET", "url": "(client-side verification)",
                "request_headers": {},
                "request_body": None, "response_status": 200,
                "response_headers": {},
                "response_body": {
                    "verification": "SHA-256(response_body_bytes) == s256 header value",
                    "blob_bytes_preview": f"{json.dumps(mission_blob, separators=(',',':'))[:64]}…",
                    "computed_s256": s256,
                    "header_s256": s256,
                    "match": True,
                },
                "tokens": [], "signature": None,
                "annotations": [
                    "Agent verifies: SHA-256(response body bytes) == s256 from AAuth-Mission header.",
                    "This binds the mission text to an immutable fingerprint.",
                    "Agent caches: approver URL + s256 for use in resource requests.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("missions-lifecycle", scenario)


def generate_missions_proactive() -> None:
    print("Generating: missions-proactive-authz (Phase 10)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    as_priv, _, _, _ = make_keypair("as-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"
    mission_blob, s256 = _mission_blob_and_s256()

    mission_claim = {"approver": ps_id, "s256": s256}
    agent_token = create_agent_token(
        iss=agent_id, sub="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=agent_priv, kid=kid, ps=ps_id,
    )
    resource_token = create_resource_token(
        iss=resource_id, aud=as_id, agent=agent_id, agent_jkt=agent_jkt,
        scope="read", private_key=as_priv, kid="as-key-1", mission=mission_claim,
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id, agent="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as_priv, kid="as-key-1",
        scope="read", mission=mission_claim, act={"sub": agent_id},
    )

    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()
    mission_header = f'approver="{ps_id}"; s256="{s256}"'

    scenario = {
        "id": "missions-proactive-authz",
        "title": "Proactive Authorization with Mission Context",
        "description": (
            "After mission approval, the agent proactively requests a resource token via POST /authorize. "
            "The AAuth-Mission header is included, and the mission claim flows through the entire token chain: "
            "resource token → auth token. Each participant can verify the mission s256 at every hop."
        ),
        "spec_section": "§ Proactive Resource Authorization",
        "category": "missions",
        "demo_phase": 10,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
        ],
        "mission_blob": {
            "title": "Mission Context",
            "description": "Approved mission reused during proactive authorization.",
            "markdown": mission_blob["description"],
            "tools": mission_blob["tools"],
            "approver": ps_id,
            "s256": s256,
            "capabilities": ["clarification", "interaction"],
        },
        "token_flow": [
            {
                "token": "resource-token",
                "label": "Resource Token",
                "tokenType": "aa-resource+jwt",
                "accent": "resource",
                "events": [
                    {"step": 3, "participant": "resource", "label": "Issued with mission claim", "kind": "issued"},
                    {"step": 4, "participant": "agent", "label": "Forwarded through the PS", "kind": "forwarded"},
                ],
            },
            {
                "token": "auth-token",
                "label": "Auth Token",
                "tokenType": "aa-auth+jwt",
                "accent": "auth",
                "events": [
                    {"step": 4, "participant": "as", "label": "Minted with mission claim intact", "kind": "issued"},
                    {"step": 5, "participant": "agent", "label": "Presented to the resource", "kind": "presented"},
                ],
            },
            {
                "token": "agent-token",
                "label": "Agent Token",
                "tokenType": "aa-agent+jwt",
                "accent": "agent",
                "events": [
                    {"step": 4, "participant": "ps", "label": "Used during federation to AS", "kind": "presented"},
                ],
            },
        ],
        "s256_chain": [
            {
                "label": "Mission Approval",
                "source": "AAuth-Mission header",
                "s256": s256,
                "detail": "The approved mission reference is the source of truth for later proactive authorization.",
            },
            {
                "label": "Resource Token Claim",
                "source": "aa-resource+jwt mission.s256",
                "s256": s256,
                "detail": "The resource preserves the mission reference when minting the proactive resource token.",
            },
            {
                "label": "Auth Token Claim",
                "source": "aa-auth+jwt mission.s256",
                "s256": s256,
                "detail": "The Access Server carries the same mission hash into the auth token after federation.",
            },
            {
                "label": "Final Access Check",
                "source": "AAuth-Mission + aa-auth+jwt",
                "s256": s256,
                "detail": "At resource access time the mission header and token claim can be compared directly.",
            },
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Mission already approved by PS",
                "method": "POST", "url": f"{ps_id}/mission",
                "request_headers": {
                    "Content-Type": "application/json",
                    "AAuth-Capabilities": "clarification, interaction",
                    **sig_headers(sig_key, sig_input, 50),
                },
                "request_body": mission_blob,
                "response_status": 200,
                "response_headers": {
                    "AAuth-Mission": mission_header,
                    "AAuth-Capabilities": "clarification, interaction, tool-approval",
                    "Content-Type": "application/json",
                },
                "response_body": mission_blob,
                "tokens": [],
                "signature": None,
                "annotations": [
                    "Phase 5.2 begins from an approved mission produced by the Phase 5.1 flow.",
                    "The approver URL and s256 from AAuth-Mission are what propagate through the later token chain.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "resource",
                "label": "POST /authorize with AAuth-Mission",
                "method": "POST", "url": f"{resource_id}/authorize",
                "request_headers": {
                    "Content-Type": "application/json",
                    "AAuth-Mission": mission_header,
                    "AAuth-Capabilities": "clarification, interaction",
                    **sig_headers(sig_key, sig_input, 51),
                },
                "request_body": {"scope": "read"},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"resource_token": resource_token},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Agent proactively requests a resource token BEFORE accessing the resource.",
                    "AAuth-Mission header carries the approved mission reference.",
                    f"s256 = {s256[:24]}… — immutable fingerprint of the mission blob.",
                    "The resource checks the mission header and prepares to embed the same mission claim in the token it returns.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "resource", "to": "agent",
                "label": "Resource issues mission-bound resource token",
                "method": "POST", "url": f"{resource_id}/authorize",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {"resource_token": resource_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"resource_token": resource_token},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "The aa-resource+jwt now contains mission={approver, s256}.",
                    "This is the first token in the chain carrying the mission reference forward.",
                ],
                "is_response": True,
            },
            {
                "step": 4, "from": "agent", "to": "ps",
                "label": "PS federates mission-bound token to AS",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(sig_key, sig_input, 52),
                },
                "request_body": {"resource_token": resource_token, "agent_token": agent_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [
                    token_fixture("Resource Token", resource_token),
                    token_fixture("Agent Token", agent_token),
                    token_fixture("Auth Token", auth_token),
                ],
                "signature": None,
                "annotations": [
                    "The agent hands the mission-bound resource token to the PS for normal federation.",
                    "The AS observes the mission claim in the resource token and carries it into the auth token unchanged.",
                    "The resulting aa-auth+jwt now contains both mission and act claims.",
                ],
                "is_response": False,
            },
            {
                "step": 5, "from": "agent", "to": "resource",
                "label": "Access resource with mission-scoped auth token",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token[:40]}…",
                    "AAuth-Mission": mission_header,
                    **sig_headers(sig_key, sig_input, 53),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "message": "Access granted within mission context!",
                    "mission_verified": True,
                    "s256_match": True,
                },
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "Resource verifies auth token mission.s256 == AAuth-Mission header s256.",
                    "Resource can now make access decisions with full mission context.",
                    "Mission context is preserved end-to-end: proposal → AAuth-Mission header → resource token → auth token → access.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("missions-proactive-authz", scenario)


def generate_missions_end_to_end() -> None:
    print("Generating: missions-end-to-end (Phase 12)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    as_priv, _, as_jwk, _ = make_keypair("as-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"
    mission_blob, s256 = _mission_blob_and_s256()

    mission_claim = {"approver": ps_id, "s256": s256}
    resource_token = create_resource_token(
        iss=resource_id, aud=as_id, agent=agent_id, agent_jkt=agent_jkt,
        scope="read", private_key=as_priv, kid="as-key-1", mission=mission_claim,
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id, agent="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as_priv, kid="as-key-1",
        scope="read", mission=mission_claim,
    )
    ps_metadata = {
        "person_server": ps_id,
        "token_endpoint": f"{ps_id}/token",
        "mission_endpoint": f"{ps_id}/mission",
        "jwks_uri": f"{ps_id}/jwks.json",
    }
    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()
    mission_header = f'approver="{ps_id}"; s256="{s256}"'

    scenario = {
        "id": "missions-end-to-end",
        "title": "Full Mission Lifecycle (End-to-End)",
        "description": (
            "The complete mission lifecycle: PS metadata discovery → mission proposal → approval "
            "→ proactive authorization → PS-AS federation → resource access. "
            "The s256 mission fingerprint flows through every token and header."
        ),
        "spec_section": "§ Mission Lifecycle",
        "category": "missions",
        "demo_phase": 12,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "ps",
                "label": "Discover PS metadata",
                "method": "GET", "url": f"{ps_id}/.well-known/aauth-person.json",
                "request_headers": {"Host": "127.0.0.1:8004"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": ps_metadata,
                "tokens": [], "signature": None,
                "annotations": ["Agent discovers mission_endpoint and token_endpoint from PS well-known metadata."],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "ps",
                "label": "POST mission proposal → approved + s256",
                "method": "POST", "url": f"{ps_id}/mission",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(sig_key, sig_input, 60),
                },
                "request_body": mission_blob,
                "response_status": 200,
                "response_headers": {
                    "Content-Type": "application/json",
                    "AAuth-Mission": f'approver="{ps_id}"; s256="{s256}"',
                },
                "response_body": mission_blob,
                "tokens": [], "signature": None,
                "annotations": [
                    f"PS approves mission. s256 = SHA-256(blob) = {s256[:24]}…",
                    "Agent stores approver URL + s256 for all subsequent requests.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "agent", "to": "resource",
                "label": "POST /authorize with AAuth-Mission → resource token",
                "method": "POST", "url": f"{resource_id}/authorize",
                "request_headers": {
                    "Content-Type": "application/json",
                    "AAuth-Mission": mission_header,
                    **sig_headers(sig_key, sig_input, 61),
                },
                "request_body": {"scope": "read"},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"resource_token": resource_token},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Resource verifies AAuth-Mission header, embeds mission claim in resource token.",
                    "Resource token payload now contains: mission: {approver, s256}.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "agent", "to": "ps",
                "label": "POST resource token to PS → auth token",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(sig_key, sig_input, 62),
                },
                "request_body": {"resource_token": resource_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Resource Token", resource_token), token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "PS forwards to AS. AS verifies mission.s256 in resource token.",
                    "AS issues auth token also containing mission claim — chain is intact.",
                ],
                "is_response": False,
            },
            {
                "step": 5, "from": "agent", "to": "resource",
                "label": "Access resource → s256 verified end-to-end",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token[:40]}…",
                    "AAuth-Mission": mission_header,
                    **sig_headers(sig_key, sig_input, 63),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "message": "Access granted!",
                    "mission_s256_in_auth_token": s256,
                    "mission_s256_in_header": s256,
                    "s256_match": True,
                },
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "Resource verifies: auth token mission.s256 == AAuth-Mission header s256.",
                    f"s256 = {s256} (unchanged from proposal to access).",
                    "Full audit trail: proposal → resource token → auth token → access decision.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("missions-end-to-end", scenario)


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_delegation() -> None:
    print("Generating: delegation (Phase 6 — agent delegation)")
    agent_server_priv, _, agent_server_jwk, _ = make_keypair("agent-server-key-1")
    delegate_priv, _, delegate_jwk, delegate_jkt = make_keypair("delegate-key-1")
    as_priv, _, as_jwk, _ = make_keypair("as-key-1")

    agent_server_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"

    # Agent server issues delegate an agent token (with delegate's key in cnf)
    delegate_agent_token = create_agent_token(
        iss=agent_server_id,
        sub="aauth:delegate-1@127.0.0.1",
        cnf_jwk=delegate_jwk,
        private_key=agent_server_priv,
        kid="agent-server-key-1",
    )
    resource_token = create_resource_token(
        iss=resource_id, aud=as_id,
        agent="aauth:delegate-1@127.0.0.1",
        agent_jkt=delegate_jkt,
        scope="read", private_key=as_priv, kid="as-key-1",
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id,
        agent="aauth:delegate-1@127.0.0.1",
        cnf_jwk=delegate_jwk, private_key=as_priv, kid="as-key-1", scope="read",
    )

    # Delegate signs with jwt scheme (its agent token in Signature-Key)
    delegate_sig_key = f'sig=jwt;jwt="{delegate_agent_token[:48]}…"'
    sig_input = standard_sig_input()

    scenario = {
        "id": "delegation",
        "title": "Agent Delegation",
        "description": (
            "A delegate obtains an agent token from the Agent Server. The agent token's cnf.jwk "
            "is the delegate's own public key — binding the token to the delegate's signing key. "
            "The delegate then uses sig=jwt (agent token in Signature-Key) to access resources. "
            "From the resource's perspective, the delegate IS the agent."
        ),
        "spec_section": "§ Agent Delegation",
        "category": "advanced",
        "demo_phase": 6,
        "participants": [
            {"id": "agent-server", "label": "Agent Server", "type": "agent", "port": 8001},
            {"id": "delegate", "label": "Delegate", "type": "delegate"},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
        ],
        "steps": [
            {
                "step": 1, "from": "delegate", "to": "agent-server",
                "label": "Request agent token (delegate's key in cnf)",
                "method": "POST", "url": f"{agent_server_id}/delegate/token",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {"delegate_jwk": delegate_jwk},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"agent_token": delegate_agent_token},
                "tokens": [token_fixture("Delegate Agent Token", delegate_agent_token)],
                "signature": None,
                "annotations": [
                    "Delegate requests an agent token from the Agent Server.",
                    "Agent Server issues aa-agent+jwt with cnf.jwk = delegate's public key.",
                    "sub = aauth:delegate-1@127.0.0.1 (delegate identifier, not agent server).",
                    "The delegate now has a token that asserts its identity + binds its key.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "delegate", "to": "resource",
                "label": "Request resource (sig=jwt with delegate's agent token)",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    "Host": "127.0.0.1:8002",
                    "Signature-Key": delegate_sig_key,
                    "Signature-Input": f"sig={sig_input}",
                    "Signature": f"sig=:{fake_sig(70)}:",
                },
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{resource_token[:48]}…"',
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("Delegate Agent Token", delegate_agent_token), token_fixture("Resource Token", resource_token)],
                "signature": {
                    "scheme": "jwt",
                    "signature_base": (
                        '"@method": GET\n"@authority": 127.0.0.1:8002\n"@path": /data\n'
                        f'"signature-key": {delegate_sig_key}\n"@signature-params": {sig_input}'
                    ),
                    "signature_input": f"sig={sig_input}",
                    "signature_key": delegate_sig_key,
                    "covered_components": ["@method", "@authority", "@path", "signature-key"],
                },
                "annotations": [
                    "Delegate signs with sig=jwt — the agent token is embedded in Signature-Key.",
                    "Delegate signs with its own private key (matching cnf.jwk in the agent token).",
                    "Resource can verify: token's cnf.jwk matches the key used to sign.",
                    "Resource issues resource token with agent = aauth:delegate-1@127.0.0.1.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "delegate", "to": "as",
                "label": "Exchange resource token → auth token",
                "method": "POST", "url": f"{as_id}/token",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {"resource_token": resource_token, "agent_token": delegate_agent_token},
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": [
                    "Delegate sends resource token + agent token to AS.",
                    "AS verifies agent_jkt in resource token == SHA-256(cnf.jwk) in agent token.",
                    "Auth token agent = aauth:delegate-1@127.0.0.1 — delegate IS the agent from resource's view.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "delegate", "to": "resource",
                "label": "Access resource with auth token → 200",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token[:40]}…",
                    "Signature-Key": delegate_sig_key,
                    "Signature": f"sig=:{fake_sig(71)}:",
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"message": "Hello, delegate!", "agent": "aauth:delegate-1@127.0.0.1"},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": ["Resource sees agent = delegate identifier — delegate identity is established."],
                "is_response": False,
            },
        ],
    }
    write_scenario("delegation", scenario)


def generate_call_chaining() -> None:
    print("Generating: call-chaining (Phase 7)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    r1_priv, _, r1_jwk, r1_jkt = make_keypair("r1-key-1")
    as1_priv, _, as1_jwk, _ = make_keypair("as1-key-1")
    as2_priv, _, as2_jwk, _ = make_keypair("as2-key-1")

    agent_id = "http://127.0.0.1:8001"
    r1_id = "http://127.0.0.1:8002"
    as1_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    r2_id = "http://127.0.0.1:8005"
    as2_id = "http://127.0.0.1:8006"

    # Auth token for Agent → R1
    auth_token_r1 = create_auth_token(
        iss=as1_id, aud=r1_id, agent="aauth:agent-8001@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as1_priv, kid="as1-key-1", scope="read",
    )
    # Resource token R2 issued to R1 (acting as agent)
    r2_resource_token = create_resource_token(
        iss=r2_id, aud=as2_id, agent=r1_id, agent_jkt=r1_jkt,
        scope="read", private_key=as2_priv, kid="as2-key-1",
    )
    # Auth token for R1 → R2, with nested act claim
    act_chain = {"sub": "aauth:agent-8002@127.0.0.1", "act": {"sub": "aauth:agent-8001@127.0.0.1"}}
    auth_token_r2 = create_auth_token(
        iss=as2_id, aud=r2_id,
        agent="aauth:agent-8002@127.0.0.1",
        cnf_jwk=r1_jwk, private_key=as2_priv, kid="as2-key-1",
        scope="read", act=act_chain,
    )

    agent_sig_key = jwks_uri_sig_key(agent_id, "agent-key-1")
    r1_sig_key = jwks_uri_sig_key(r1_id, "r1-key-1")
    sig_input = standard_sig_input()

    scenario = {
        "id": "call-chaining",
        "title": "Call Chaining (R1 acts as Agent to R2)",
        "description": (
            "Resource 1 needs data from Resource 2 to fulfil the agent's request. "
            "R1 acts as an agent to call R2 — sending the R2 resource token + upstream auth token to the PS. "
            "The resulting auth token has nested act claims recording the full delegation chain."
        ),
        "spec_section": "§ Call Chaining",
        "category": "advanced",
        "demo_phase": 7,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "r1", "label": "Resource 1", "type": "resource", "port": 8002},
            {"id": "as1", "label": "Access Server 1", "type": "access-server", "port": 8003},
            {"id": "ps", "label": "Person Server", "type": "person-server", "port": 8004},
            {"id": "r2", "label": "Resource 2", "type": "resource", "port": 8005},
            {"id": "as2", "label": "Access Server 2", "type": "access-server", "port": 8006},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "r1",
                "label": "Agent → R1: autonomous flow → auth token",
                "method": "GET", "url": f"{r1_id}/data",
                "request_headers": {"Host": "127.0.0.1:8002", **sig_headers(agent_sig_key, sig_input, 80)},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"status": "processing", "note": "R1 needs data from R2"},
                "tokens": [token_fixture("Auth Token (Agent→R1)", auth_token_r1)],
                "signature": None,
                "annotations": [
                    "Agent accesses R1 via normal autonomous flow (→ PS → AS1 → auth token).",
                    "R1 grants access but needs data from R2 to fulfil the request.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "r1", "to": "r2",
                "label": "R1 requests R2 → 401 + R2 resource token",
                "method": "GET", "url": f"{r2_id}/data",
                "request_headers": {"Host": "127.0.0.1:8005", **sig_headers(r1_sig_key, sig_input, 81)},
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{r2_resource_token[:48]}…"',
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("R2 Resource Token", r2_resource_token)],
                "signature": None,
                "annotations": [
                    "R1 signs request with its own identity (sig=jwks_uri).",
                    "R2 issues resource token: agent=R1, agent_jkt=R1 key thumbprint, aud=AS2.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "r1", "to": "ps",
                "label": "R1 sends R2 resource token + upstream auth token to PS",
                "method": "POST", "url": f"{ps_id}/token",
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(r1_sig_key, sig_input, 82),
                },
                "request_body": {
                    "resource_token": r2_resource_token,
                    "upstream_token": auth_token_r1,
                },
                "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token_r2},
                "tokens": [
                    token_fixture("R2 Resource Token", r2_resource_token),
                    token_fixture("Upstream Auth Token (Agent→R1)", auth_token_r1),
                    token_fixture("Auth Token (R1→R2)", auth_token_r2),
                ],
                "signature": None,
                "annotations": [
                    "R1 sends both: the R2 resource token AND the upstream auth token (proving the original agent).",
                    "PS evaluates the chain: original agent → R1 → R2.",
                    "PS federates to AS2 with full chain context.",
                    "AS2 issues auth token with nested act claims.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "r1", "to": "r2",
                "label": "R1 accesses R2 with chained auth token",
                "method": "GET", "url": f"{r2_id}/data",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token_r2[:40]}…",
                    **sig_headers(r1_sig_key, sig_input, 83),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"data": "R2 data", "agent_chain": "agent-8001 → resource-8002"},
                "tokens": [token_fixture("Auth Token (R1→R2) — with nested act", auth_token_r2)],
                "signature": None,
                "annotations": [
                    "Auth token act claim: {sub: 'aauth:agent-8002@…', act: {sub: 'aauth:agent-8001@…'}}",
                    "R2 sees: current actor = R1, acting on behalf of = original agent.",
                    "Full delegation chain is cryptographically verifiable.",
                ],
                "is_response": False,
            },
            {
                "step": 5, "from": "r1", "to": "agent",
                "label": "R1 returns combined result to agent",
                "method": "GET", "url": "(response to step 1)",
                "request_headers": {},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"result": "Combined data from R1 + R2", "chain_verified": True},
                "tokens": [], "signature": None,
                "annotations": ["R1 combines its own data with R2's data and returns to the original agent."],
                "is_response": True,
            },
        ],
    }
    write_scenario("call-chaining", scenario)


def generate_clarification() -> None:
    print("Generating: clarification (Phase 8 — clarification chat)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    as_priv, _, as_jwk, _ = make_keypair("as-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"
    kid = "agent-key-1"

    resource_token = create_resource_token(
        iss=resource_id, aud=as_id, agent=agent_id, agent_jkt=agent_jkt,
        scope="read", private_key=as_priv, kid="as-key-1",
    )
    auth_token = create_auth_token(
        iss=as_id, aud=resource_id, agent="aauth:local@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as_priv, kid="as-key-1", scope="read",
    )

    interaction_code = "c7a2f1b4e3d09865"
    pending_url = f"{as_id}/pending/{interaction_code}"
    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()

    scenario = {
        "id": "clarification",
        "title": "Clarification Chat During Consent",
        "description": (
            "During user consent, the Access Server poses a clarification question to the agent. "
            "If the agent declares clarification support via AAuth-Capabilities, it responds to the question "
            "before the user grants consent. If unsupported, the AS skips the clarification step."
        ),
        "spec_section": "§ Clarification",
        "category": "advanced",
        "demo_phase": 8,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
            {"id": "as", "label": "Access Server", "type": "access-server", "port": 8003},
            {"id": "user", "label": "User", "type": "user"},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Request resource → 401 + resource token",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    **sig_headers(sig_key, sig_input, 90),
                    "AAuth-Capabilities": "clarification, interaction",
                },
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{resource_token[:48]}…"',
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("Resource Token", resource_token)],
                "signature": None,
                "annotations": [
                    "Agent declares AAuth-Capabilities: clarification — signals it can respond to questions.",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "agent", "to": "as",
                "label": "POST resource token → 202 + clarification question",
                "method": "POST", "url": f"{as_id}/token",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {"resource_token": resource_token},
                "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "pending": pending_url,
                    "requirement": "clarification",
                    "question": "What specific data will you read from this resource, and why?",
                },
                "tokens": [], "signature": None,
                "annotations": [
                    "AS returns 202 + a clarification question instead of an interaction URL.",
                    "Agent must answer before AS will present consent to the user.",
                ],
                "is_response": False,
            },
            {
                "step": 3, "from": "agent", "to": "as",
                "label": "POST clarification response to pending URL",
                "method": "POST", "url": pending_url,
                "request_headers": {
                    "Content-Type": "application/json",
                    **sig_headers(sig_key, sig_input, 91),
                },
                "request_body": {
                    "clarification_response": "I will read the Q2 sales summary report to prepare an executive briefing. No PII will be accessed.",
                },
                "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "pending": pending_url,
                    "interaction": f"{as_id}/interact?code={interaction_code}",
                    "note": "Clarification recorded. User consent required.",
                },
                "tokens": [], "signature": None,
                "annotations": [
                    "Agent posts its answer to the pending URL.",
                    "AS records the clarification and now presents enhanced consent context to the user.",
                    "User sees: agent identity + scope + clarification Q&A.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "user", "to": "as",
                "label": "User reviews clarification context → approves",
                "method": "GET", "url": f"{as_id}/interact?code={interaction_code}",
                "request_headers": {"Cookie": "session=xyz"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "text/html"},
                "response_body": "<!-- Consent page shows: agent ID, scope, clarification Q&A. User clicks Approve. -->",
                "tokens": [], "signature": None,
                "annotations": ["User sees the clarification answer as part of the consent context."],
                "is_response": False,
            },
            {
                "step": 5, "from": "agent", "to": "as",
                "label": "Poll pending URL → auth token",
                "method": "GET", "url": pending_url,
                "request_headers": {**sig_headers(sig_key, sig_input, 92)},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token},
                "tokens": [token_fixture("Auth Token", auth_token)],
                "signature": None,
                "annotations": ["User approved — polling returns auth token."],
                "is_response": False,
            },
        ],
    }
    write_scenario("clarification", scenario)


def generate_interaction_chaining() -> None:
    print("Generating: interaction-chaining (Phase 9)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")
    r1_priv, _, r1_jwk, r1_jkt = make_keypair("r1-key-1")
    as1_priv, _, as1_jwk, _ = make_keypair("as1-key-1")
    as2_priv, _, as2_jwk, _ = make_keypair("as2-key-1")

    agent_id = "http://127.0.0.1:8001"
    r1_id = "http://127.0.0.1:8002"
    as1_id = "http://127.0.0.1:8003"
    r2_id = "http://127.0.0.1:8004"
    as2_id = "http://127.0.0.1:8005"

    auth_token_r1 = create_auth_token(
        iss=as1_id, aud=r1_id, agent="aauth:agent-8001@127.0.0.1",
        cnf_jwk=agent_jwk, private_key=as1_priv, kid="as1-key-1", scope="read",
    )
    r2_resource_token = create_resource_token(
        iss=r2_id, aud=as2_id, agent=r1_id, agent_jkt=r1_jkt,
        scope="read", private_key=as2_priv, kid="as2-key-1",
    )
    act_chain = {"sub": "aauth:agent-8002@127.0.0.1", "act": {"sub": "aauth:agent-8001@127.0.0.1"}}
    auth_token_r2 = create_auth_token(
        iss=as2_id, aud=r2_id, agent="aauth:agent-8002@127.0.0.1",
        cnf_jwk=r1_jwk, private_key=as2_priv, kid="as2-key-1",
        scope="read", act=act_chain,
    )

    interact_code_r1 = "r1_chain_9a2f"
    interact_code_as2 = "as2_interact_b3e1"
    agent_sig_key = jwks_uri_sig_key(agent_id, "agent-key-1")
    r1_sig_key = jwks_uri_sig_key(r1_id, "r1-key-1")
    sig_input = standard_sig_input()

    scenario = {
        "id": "interaction-chaining",
        "title": "Interaction Chaining (202 Bubbles Back)",
        "description": (
            "R1 calls R2, but R2's AS requires user consent. Instead of blocking, R1 bubbles the "
            "202 interaction back to the original agent. The agent's interaction URL redirects through R1 "
            "to AS2. R1 polls AS2 in parallel while the agent polls R1."
        ),
        "spec_section": "§ Interaction Chaining",
        "category": "advanced",
        "demo_phase": 9,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "r1", "label": "Resource 1", "type": "resource", "port": 8002},
            {"id": "as1", "label": "Access Server 1", "type": "access-server", "port": 8003},
            {"id": "r2", "label": "Resource 2", "type": "resource", "port": 8004},
            {"id": "as2", "label": "Access Server 2", "type": "access-server", "port": 8005},
            {"id": "user", "label": "User", "type": "user"},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "r1",
                "label": "Agent → R1 (with auth token from AS1)",
                "method": "GET", "url": f"{r1_id}/data",
                "request_headers": {
                    "AAuth-Access": f"token={auth_token_r1[:40]}…",
                    **sig_headers(agent_sig_key, sig_input, 100),
                },
                "request_body": None, "response_status": 202,
                "response_headers": {
                    "Content-Type": "application/json",
                },
                "response_body": {
                    "pending": f"{r1_id}/pending/{interact_code_r1}",
                    "interaction": f"{r1_id}/interact?code={interact_code_r1}",
                },
                "tokens": [token_fixture("Auth Token (Agent→R1)", auth_token_r1)],
                "signature": None,
                "annotations": [
                    "Agent accesses R1 with AS1-issued auth token.",
                    "R1 needs data from R2, but R2's AS requires user consent.",
                    "R1 returns 202 + interaction URL (pointing to R1's /interact endpoint).",
                ],
                "is_response": False,
            },
            {
                "step": 2, "from": "r1", "to": "r2",
                "label": "R1 calls R2 → 401 + R2 resource token",
                "method": "GET", "url": f"{r2_id}/data",
                "request_headers": {**sig_headers(r1_sig_key, sig_input, 101)},
                "request_body": None, "response_status": 401,
                "response_headers": {
                    "AAuth-Requirement": f'requirement=auth_token; resource_token="{r2_resource_token[:48]}…"',
                },
                "response_body": {"error": "auth_token_required"},
                "tokens": [token_fixture("R2 Resource Token", r2_resource_token)],
                "signature": None,
                "annotations": ["R1 attempts to call R2 — R2 requires an auth token."],
                "is_response": False,
            },
            {
                "step": 3, "from": "r1", "to": "as2",
                "label": "R1 sends R2 resource token → AS2 returns 202",
                "method": "POST", "url": f"{as2_id}/token",
                "request_headers": {"Content-Type": "application/json"},
                "request_body": {"resource_token": r2_resource_token, "upstream_token": auth_token_r1},
                "response_status": 202,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "pending": f"{as2_id}/pending/{interact_code_as2}",
                    "interaction": f"{as2_id}/interact?code={interact_code_as2}",
                },
                "tokens": [], "signature": None,
                "annotations": [
                    "AS2 requires user consent for R1 to access R2.",
                    "AS2 returns 202 + interaction URL (pointing to AS2 directly).",
                    "R1 will poll AS2's pending URL while bubbling the 202 back to the agent.",
                ],
                "is_response": False,
            },
            {
                "step": 4, "from": "user", "to": "r1",
                "label": "User opens R1 /interact → redirected to AS2",
                "method": "GET", "url": f"{r1_id}/interact?code={interact_code_r1}",
                "request_headers": {"Cookie": "session=user123"},
                "request_body": None, "response_status": 302,
                "response_headers": {
                    "Location": f"{as2_id}/interact?code={interact_code_as2}",
                },
                "response_body": None,
                "tokens": [], "signature": None,
                "annotations": [
                    "User visits R1's /interact URL (from agent's 202 response).",
                    "R1 redirects user to AS2's actual interaction page.",
                    "This chaining is transparent to the user.",
                ],
                "is_response": False,
            },
            {
                "step": 5, "from": "user", "to": "as2",
                "label": "User approves at AS2 consent page",
                "method": "GET", "url": f"{as2_id}/interact?code={interact_code_as2}",
                "request_headers": {"Cookie": "session=user123"},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "text/html"},
                "response_body": "<!-- AS2 consent: R1 (acting as agent) → R2. User approves. -->",
                "tokens": [], "signature": None,
                "annotations": ["User approves R1's access to R2 at AS2's consent page."],
                "is_response": False,
            },
            {
                "step": 6, "from": "r1", "to": "as2",
                "label": "R1 polls AS2 → auth token for R2",
                "method": "GET", "url": f"{as2_id}/pending/{interact_code_as2}",
                "request_headers": {**sig_headers(r1_sig_key, sig_input, 102)},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"auth_token": auth_token_r2},
                "tokens": [token_fixture("Auth Token (R1→R2) — chained", auth_token_r2)],
                "signature": None,
                "annotations": ["R1 receives auth token for R2 — includes nested act claims."],
                "is_response": False,
            },
            {
                "step": 7, "from": "agent", "to": "r1",
                "label": "Agent polls R1 → 200 final result",
                "method": "GET", "url": f"{r1_id}/pending/{interact_code_r1}",
                "request_headers": {**sig_headers(agent_sig_key, sig_input, 103)},
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {"result": "Combined data from R1 + R2", "chain_complete": True},
                "tokens": [], "signature": None,
                "annotations": [
                    "Agent polls R1's pending URL (was given in step 1's 202 response).",
                    "R1 has now completed its R2 call — returns the combined result.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("interaction-chaining", scenario)


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY-BASED ACCESS (2-party, no tokens)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_identity_based() -> None:
    print("Generating: identity-based (2-party, identity-only access)")
    agent_priv, _, agent_jwk, agent_jkt = make_keypair("agent-key-1")

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    kid = "agent-key-1"

    sig_key = jwks_uri_sig_key(agent_id, kid)
    sig_input = standard_sig_input()

    scenario = {
        "id": "identity-based",
        "title": "Identity-Based Access (2-party)",
        "description": (
            "The simplest resource access mode. The agent signs the request with its identity "
            "(sig=jwks_uri), the resource verifies the signature, and makes an access decision "
            "based on the agent identity alone — no tokens, no Person Server, no Access Server."
        ),
        "spec_section": "§ Identity-Based Access",
        "category": "access",
        "demo_phase": None,
        "participants": [
            {"id": "agent", "label": "Agent", "type": "agent", "port": 8001},
            {"id": "resource", "label": "Resource", "type": "resource", "port": 8002},
        ],
        "steps": [
            {
                "step": 1, "from": "agent", "to": "resource",
                "label": "Signed request (sig=jwks_uri) → direct access decision",
                "method": "GET", "url": f"{resource_id}/data",
                "request_headers": {
                    "Host": "127.0.0.1:8002",
                    **sig_headers(sig_key, sig_input, 5),
                },
                "request_body": None, "response_status": 200,
                "response_headers": {"Content-Type": "application/json"},
                "response_body": {
                    "message": "Access granted based on agent identity!",
                    "agent": agent_id,
                    "jkt": agent_jkt,
                    "policy_match": "agent in allowed_agents",
                },
                "tokens": [],
                "signature": {
                    "scheme": "jwks_uri",
                    "signature_base": (
                        '"@method": GET\n"@authority": 127.0.0.1:8002\n"@path": /data\n'
                        f'"signature-key": {sig_key}\n"@signature-params": {sig_input}'
                    ),
                    "signature_input": f"sig={sig_input}",
                    "signature_key": sig_key,
                    "covered_components": ["@method", "@authority", "@path", "signature-key"],
                },
                "annotations": [
                    "No token exchange needed — resource grants access based on verified identity.",
                    "Resource checks: is this agent in my allowed_agents list?",
                    "Use case: replacing API keys with cryptographic identity (zero infrastructure).",
                    "Compare with federated mode: same signing, but resource defers to AS for policy.",
                ],
                "is_response": False,
            },
        ],
    }
    write_scenario("identity-based", scenario)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

GENERATORS = {
    "pseudonymous": generate_pseudonymous,
    "identity": generate_identity,
    "identity-based": generate_identity_based,
    "federated": generate_federated,
    "user-delegation": generate_user_delegation,
    "ps-managed": generate_ps_managed,
    "missions-lifecycle": generate_missions_lifecycle,
    "missions-proactive-authz": generate_missions_proactive,
    "missions-end-to-end": generate_missions_end_to_end,
    "delegation": generate_delegation,
    "call-chaining": generate_call_chaining,
    "clarification": generate_clarification,
    "interaction-chaining": generate_interaction_chaining,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate AAuth demo UI scenario fixtures")
    parser.add_argument("--scenario", choices=list(GENERATORS.keys()), help="Generate one scenario")
    args = parser.parse_args()

    print(f"Output: {OUTPUT_DIR}\n")
    targets = {args.scenario: GENERATORS[args.scenario]} if args.scenario else GENERATORS
    for gen in targets.values():
        gen()
    print(f"\nDone. {len(targets)} fixture(s) written.")


if __name__ == "__main__":
    main()
