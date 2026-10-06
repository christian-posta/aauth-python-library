"""Draft -11 agent token issuance and verification."""

import time
import uuid
from .common import (
    encode_jwt,
    validate_algorithm,
    validate_server_identifier,
    validate_agent_identifier,
    verify_agent_claims,
)
from ..errors import TokenError


def create_agent_token(
    iss,
    sub,
    cnf_jwk,
    private_key,
    kid,
    exp=None,
    aud=None,
    aud_sub=None,
    ps=None,
    parent_agent=None,
    parent_iss=None,
    parent_token=None,
    jwks_fetcher=None,
):
    validate_server_identifier(iss)
    validate_agent_identifier(sub)
    validate_algorithm(cnf_jwk)
    now = int(time.time())
    exp = now + 3600 if exp is None else exp
    if type(exp) is not int or exp <= now:
        raise TokenError("Invalid agent token expiration")
    p = dict(
        iss=iss,
        sub=sub,
        dwk="aauth-agent.json",
        jti=str(uuid.uuid4()),
        iat=now,
        exp=exp,
        cnf={"jwk": cnf_jwk},
    )
    if ps is not None:
        p["ps"] = validate_server_identifier(ps)
    if parent_agent is not None or parent_token is not None:
        if not parent_token or not jwks_fetcher:
            raise TokenError("Sub-agent issuance requires a verified parent token")
        parent = verify_agent_claims(parent_token, jwks_fetcher)
        parent_agent = parent_agent or parent["sub"]
        validate_agent_identifier(parent_agent)
        if (
            parent.get("parent_agent")
            or parent["iss"] != iss
            or parent["sub"] != parent_agent
        ):
            raise TokenError(
                "Sub-agent parent must be a top-level agent under the same issuer"
            )
        parent_local, domain = parent_agent[6:].split("@", 1)
        child_local, child_domain = sub[6:].split("@", 1)
        if (
            child_domain != domain
            or not child_local.startswith(parent_local + "+")
            or len(child_local) <= len(parent_local) + 1
        ):
            raise TokenError(
                "Sub-agent identifier requires parent local part plus discriminator"
            )
        from ..keys.jwk import calculate_jwk_thumbprint

        if calculate_jwk_thumbprint(cnf_jwk) == calculate_jwk_thumbprint(
            parent["cnf"]["jwk"]
        ):
            raise TokenError("Sub-agent requires its own key")
        p["parent_agent"] = parent_agent
    if aud is not None:
        p["aud"] = aud
    if aud_sub is not None:
        p["aud_sub"] = aud_sub
    return encode_jwt(p, private_key, kid, "aa-agent+jwt")


def verify_agent_token(token, jwks_fetcher, expected_aud=None):
    return verify_agent_claims(token, jwks_fetcher, expected_aud)
