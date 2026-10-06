"""Parent and upstream token bindings for draft -11 delegation."""

from .common import parse_jwt, verify_token
from ..keys.jwk import calculate_jwk_thumbprint
from ..errors import TokenError


def verify_subagent_token(parent_token, subagent_token, jwks_fetcher):
    parent = verify_token(parent_token, jwks_fetcher, expected_typ="aa-agent+jwt")
    child = verify_token(subagent_token, jwks_fetcher, expected_typ="aa-agent+jwt")
    if (
        parent.get("parent_agent")
        or child.get("parent_agent") != parent["sub"]
        or child["iss"] != parent["iss"]
    ):
        raise TokenError(
            "Invalid single-level parent/issuer binding",
            error_code="invalid_subagent_token",
        )
    if calculate_jwk_thumbprint(child["cnf"]["jwk"]) == calculate_jwk_thumbprint(
        parent["cnf"]["jwk"]
    ):
        raise TokenError(
            "Sub-agent requires its own signing key",
            error_code="invalid_subagent_token",
        )
    return child


def verify_upstream_token(
    token,
    jwks_fetcher,
    *,
    intermediary_agent_token,
    person_server,
    trusted_access_servers=(),
    recipient_role="ps",
    revocation_checker=None,
):
    header, _ = parse_jwt(token)
    if header.get("typ") not in ("aa-person+jwt", "aa-auth+jwt"):
        raise TokenError(
            "Expected person or auth upstream token",
            error_code="invalid_upstream_token",
        )
    intermediary = verify_token(
        intermediary_agent_token, jwks_fetcher, expected_typ="aa-agent+jwt"
    )
    try:
        p = verify_token(
            token,
            jwks_fetcher,
            expected_aud=intermediary["iss"],
            revocation_checker=revocation_checker,
        )
    except TokenError as exc:
        code = {
            "expired_jwt": "expired_upstream_token",
            "revoked_jwt": "revoked_upstream_token",
        }.get(exc.error_code, "invalid_upstream_token")
        raise TokenError(str(exc), error_code=code) from exc
    ps = p["iss"] if header["typ"] == "aa-person+jwt" else p["ps"]
    if ps != person_server or recipient_role not in ("ps", "as"):
        raise TokenError("Upstream PS mismatch", error_code="invalid_upstream_token")
    if (
        recipient_role == "ps"
        and header["typ"] == "aa-auth+jwt"
        and p["iss"] not in {person_server, *trusted_access_servers}
    ):
        raise TokenError(
            "Upstream issuer was not federated by this PS",
            error_code="invalid_upstream_token",
        )
    return p
