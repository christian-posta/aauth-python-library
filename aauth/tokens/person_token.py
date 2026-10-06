"""Person token issuance and verification (draft -11 §7.1)."""

import time
from .common import (
    base_claims,
    bounded_exp,
    verify_token,
    encode_jwt,
    check_server,
    check_hash,
    validate_algorithm,
)
from ..errors import TokenError


def create_person_token(
    iss,
    aud,
    sub,
    cnf_jwk,
    private_key,
    kid,
    *,
    agent_exp,
    exp=None,
    mission_s256=None,
    mission_exp=None,
    upstream_exp=None,
    tenant=None,
):
    if type(agent_exp) is not int:
        raise TokenError("Verified agent expiration is required")
    check_server(aud)
    validate_algorithm(cnf_jwk)
    if not isinstance(sub, str) or not sub:
        raise TokenError("Person token requires directed sub")
    if mission_s256 is not None and mission_exp is None:
        raise TokenError("Mission expiration bound is required")
    now = int(time.time())
    p = base_claims(
        iss,
        "aauth-person.json",
        bounded_exp(now, exp, agent_exp, mission_exp, upstream_exp),
    )
    p.update(aud=aud, sub=sub, cnf={"jwk": cnf_jwk})
    if mission_s256 is not None:
        p["mission_s256"] = check_hash(mission_s256)
    if tenant is not None:
        p["tenant"] = tenant
    return encode_jwt(p, private_key, kid, "aa-person+jwt")


def verify_person_token(token, jwks_fetcher, **kwargs):
    return verify_token(token, jwks_fetcher, expected_typ="aa-person+jwt", **kwargs)
