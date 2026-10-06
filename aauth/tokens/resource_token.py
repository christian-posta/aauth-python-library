"""Resource tokens bound to the verified person/auth token that prompted them."""

import time
from .common import base_claims, verify_token, parse_jwt, encode_jwt, check_server
from ..keys.jwk import calculate_jwk_thumbprint
from ..errors import TokenError


def _presented(token, fetcher, resource, jkt, revocation_checker=None):
    header, _ = parse_jwt(token)
    if header.get("typ") not in ("aa-person+jwt", "aa-auth+jwt"):
        raise TokenError(
            "Expected person or auth presented_token",
            error_code="invalid_presented_token",
        )
    try:
        p = verify_token(
            token, fetcher, expected_aud=resource, revocation_checker=revocation_checker
        )
        if calculate_jwk_thumbprint(p["cnf"]["jwk"]) != jkt:
            raise TokenError("Presented confirmation key mismatch")
    except TokenError as exc:
        code = {
            "expired_jwt": "expired_presented_token",
            "revoked_jwt": "revoked_presented_token",
        }.get(exc.error_code, "invalid_presented_token")
        raise TokenError(str(exc), error_code=code) from exc
    return p, p["iss"] if header["typ"] == "aa-person+jwt" else p["ps"]


def create_resource_token(
    iss,
    aud,
    agent_jkt,
    private_key,
    kid,
    *,
    presented_token,
    jwks_fetcher,
    scope=None,
    exp=None,
    account=None,
    login_hint=None,
    interaction=None,
    revocation_checker=None,
):
    check_server(aud)
    p, ps = _presented(
        presented_token, jwks_fetcher, iss, agent_jkt, revocation_checker
    )
    now = int(time.time())
    exp = now + 300 if exp is None else exp
    if type(exp) is not int or exp <= now:
        raise TokenError("Invalid resource token expiration")
    claims = base_claims(iss, "aauth-resource.json", exp)
    claims.update(
        aud=aud, ps=ps, sub=p["sub"], presented_jti=p["jti"], agent_jkt=agent_jkt
    )
    for name in ("mission_s256", "tenant"):
        if name in p:
            claims[name] = p[name]
    for name, value in [
        ("scope", scope),
        ("account", account),
        ("login_hint", login_hint),
        ("interaction", interaction),
    ]:
        if value is not None:
            claims[name] = value
    return encode_jwt(claims, private_key, kid, "aa-resource+jwt")


def verify_resource_token(
    token,
    jwks_fetcher,
    *,
    presented_token,
    expected_aud=None,
    expected_iss=None,
    expected_ps=None,
    expected_agent_jkt=None,
    revocation_checker=None,
    mission_checker=None,
):
    try:
        p = verify_token(
            token,
            jwks_fetcher,
            expected_typ="aa-resource+jwt",
            expected_aud=expected_aud,
            expected_iss=expected_iss,
            revocation_checker=revocation_checker,
        )
    except TokenError as exc:
        code = {
            "expired_jwt": "expired_resource_token",
            "revoked_jwt": "revoked_resource_token",
        }.get(exc.error_code, "invalid_resource_token")
        raise TokenError(str(exc), error_code=code) from exc
    if expected_agent_jkt and p["agent_jkt"] != expected_agent_jkt:
        raise TokenError("agent_jkt mismatch", error_code="invalid_resource_token")
    presented, ps = _presented(
        presented_token, jwks_fetcher, p["iss"], p["agent_jkt"], revocation_checker
    )
    if expected_ps and p["ps"] != expected_ps:
        raise TokenError("PS mismatch", error_code="invalid_resource_token")
    if (
        p["ps"] != ps
        or p["sub"] != presented["sub"]
        or p["presented_jti"] != presented["jti"]
    ):
        raise TokenError(
            "Presented token binding mismatch", error_code="invalid_resource_token"
        )
    for name in ("mission_s256", "tenant"):
        if p.get(name) != presented.get(name) or (name in p) != (name in presented):
            raise TokenError(
                f"{name} binding mismatch", error_code="invalid_resource_token"
            )
    if "mission_s256" in p and expected_aud == expected_ps:
        if mission_checker is None or not mission_checker(p["mission_s256"]):
            raise TokenError("Mission is not active", error_code="mission_terminated")
    return p
