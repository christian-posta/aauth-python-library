"""Draft -11 claim validation and dependency lifetime bounds."""

import time
import uuid
from aauth_signing.tokens.common import (
    parse_jwt,
    encode_jwt,
    verify_jwt,
    validate_algorithm,
    verify_agent_claims,
)
from aauth_signing.verifier import _fetch_jwks
from ..identifiers import validate_server_identifier
from ..keys.jwk import calculate_jwk_thumbprint
from ..errors import TokenError

TYPES = {
    "aa-agent+jwt": ("aauth-agent.json",),
    "aa-person+jwt": ("aauth-person.json",),
    "aa-auth+jwt": ("aauth-person.json", "aauth-access.json"),
    "aa-resource+jwt": ("aauth-resource.json",),
}


def check_server(value):
    try:
        return validate_server_identifier(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise TokenError("Invalid server identifier", error_code="invalid_jwt") from exc


def check_hash(value):
    import re

    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise TokenError("Invalid mission_s256", error_code="invalid_jwt")
    return value


def bounded_exp(now, exp, *bounds):
    values = [
        now + 3600,
        exp if exp is not None else now + 3600,
        *[b for b in bounds if b is not None],
    ]
    if any(type(v) is not int for v in values):
        raise TokenError("Expiration bounds must be integer timestamps")
    result = min(values)
    if result <= now:
        raise TokenError("Dependency has expired", error_code="expired_jwt")
    return result


def base_claims(iss, dwk, exp):
    return dict(
        iss=check_server(iss),
        dwk=dwk,
        jti=str(uuid.uuid4()),
        iat=int(time.time()),
        exp=exp,
    )


def verify_token(
    token,
    jwks_fetcher,
    expected_typ=None,
    expected_iss=None,
    expected_aud=None,
    request_signing_jwk=None,
    revocation_checker=None,
):
    header, p = parse_jwt(token)
    typ = header.get("typ")
    if typ not in TYPES or (expected_typ and typ != expected_typ):
        raise TokenError(
            "Unexpected token type", token_type=typ, error_code="invalid_jwt"
        )
    if p.get("dwk") not in TYPES[typ]:
        raise TokenError(
            "Invalid dwk for token type", token_type=typ, error_code="invalid_jwt"
        )
    check_server(p.get("iss"))
    if expected_iss and p["iss"] != expected_iss:
        raise TokenError("Issuer mismatch", error_code="invalid_jwt")
    if typ == "aa-agent+jwt":
        p = verify_agent_claims(token, jwks_fetcher, expected_aud)
    else:
        p = verify_jwt(
            token,
            _fetch_jwks(jwks_fetcher, p["iss"], p["dwk"], header.get("kid")) or {},
        )
        check_server(p.get("aud"))
        if expected_aud and p["aud"] != expected_aud:
            raise TokenError("Audience mismatch", error_code="invalid_jwt")
        required = (
            ("ps", "sub", "presented_jti", "agent_jkt")
            if typ == "aa-resource+jwt"
            else ("sub",)
        )
        for name in required:
            if not isinstance(p.get(name), str) or not p[name]:
                raise TokenError(f"Missing or invalid {name}", error_code="invalid_jwt")
        if typ in ("aa-auth+jwt", "aa-resource+jwt"):
            check_server(p.get("ps"))
        if (
            typ == "aa-auth+jwt"
            and p["dwk"] == "aauth-person.json"
            and p["ps"] != p["iss"]
        ):
            raise TokenError(
                "PS-issued auth token ps must equal iss", error_code="invalid_jwt"
            )
        if typ in ("aa-auth+jwt", "aa-person+jwt") and p["exp"] - p["iat"] > 3600:
            raise TokenError(
                "Token lifetime exceeds one hour", error_code="invalid_jwt"
            )
    if not isinstance(p.get("jti"), str) or not p["jti"]:
        raise TokenError("Missing jti", error_code="invalid_jwt")
    if "mission_s256" in p:
        check_hash(p["mission_s256"])
    if "scope" in p and not isinstance(p["scope"], str):
        raise TokenError("Invalid scope", error_code="invalid_jwt")
    if typ != "aa-resource+jwt":
        cnf = p.get("cnf")
        if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
            raise TokenError("Missing cnf.jwk", error_code="invalid_jwt")
        validate_algorithm(cnf["jwk"])
        if request_signing_jwk and calculate_jwk_thumbprint(
            cnf["jwk"]
        ) != calculate_jwk_thumbprint(request_signing_jwk):
            raise TokenError("Confirmation key mismatch", error_code="invalid_key")
    if revocation_checker and revocation_checker(p["iss"], p["jti"]):
        raise TokenError("Token was revoked", token_type=typ, error_code="revoked_jwt")
    return p
