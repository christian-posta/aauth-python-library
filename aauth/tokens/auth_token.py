"""Draft -11 auth tokens: person identity and authorization, without agent/act."""

import time
from .common import (
    base_claims,
    bounded_exp,
    verify_token,
    parse_jwt,
    encode_jwt,
    check_server,
    check_hash,
    validate_algorithm,
)
from ..errors import TokenError


def create_auth_token(
    iss,
    aud,
    cnf_jwk,
    private_key,
    kid,
    *,
    ps,
    sub,
    agent_exp,
    presented_exp,
    scope=None,
    exp=None,
    mission_s256=None,
    mission_exp=None,
    upstream_exp=None,
    tenant=None,
    account=None,
    dwk="aauth-access.json",
):
    now = int(time.time())
    if type(agent_exp) is not int or type(presented_exp) is not int:
        raise TokenError("Verified agent and presented expirations are required")
    check_server(aud)
    check_server(ps)
    validate_algorithm(cnf_jwk)
    if not isinstance(sub, str) or not sub:
        raise TokenError("Auth token requires directed sub")
    if dwk not in ("aauth-person.json", "aauth-access.json") or (
        dwk == "aauth-person.json" and iss != ps
    ):
        raise TokenError("Invalid issuer/dwk for auth token")
    if mission_s256 is not None and dwk == "aauth-person.json" and mission_exp is None:
        raise TokenError("PS must provide mission expiration bound")
    p = base_claims(
        iss,
        dwk,
        bounded_exp(now, exp, agent_exp, presented_exp, upstream_exp, mission_exp),
    )
    p.update(aud=aud, ps=ps, sub=sub, cnf={"jwk": cnf_jwk})
    for name, value in [
        ("scope", scope),
        ("mission_s256", mission_s256),
        ("tenant", tenant),
        ("account", account),
    ]:
        if value is not None:
            p[name] = check_hash(value) if name == "mission_s256" else value
    return encode_jwt(p, private_key, kid, "aa-auth+jwt")


def parse_token_claims(token):
    header, payload = parse_jwt(token)
    return {"header": header, "payload": payload}
