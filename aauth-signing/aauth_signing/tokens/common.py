"""JWT cryptography shared by token and HTTP signature verification.

Use a private PyJWS registry for RFC 9864 Ed25519; do not mutate PyJWT's global
algorithm registry. The wire identifier is Ed25519, never EdDSA.
"""

import json
import math
import time
import jwt
from jwt.api_jws import PyJWS
from jwt.algorithms import OKPAlgorithm
from ..errors import TokenError
from ..keys.jwk import jwk_to_public_key, public_key_to_jwk

_JWS = PyJWS()
_JWS.register_algorithm("Ed25519", OKPAlgorithm())
_ALGS = {
    "Ed25519": ("OKP", "Ed25519"),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
}


def validate_algorithm(jwk, expected_alg=None):
    alg = jwk.get("alg")
    if alg not in _ALGS:
        raise TokenError(
            "Missing or unsupported fully-specified alg",
            error_code="unsupported_algorithm",
        )
    if (jwk.get("kty"), jwk.get("crv")) != _ALGS[alg] or (
        expected_alg and alg != expected_alg
    ):
        raise TokenError(
            "Key type, curve, or algorithm mismatch", error_code="invalid_key"
        )
    try:
        jwk_to_public_key(jwk)
    except Exception as exc:
        raise TokenError(
            "Invalid public key material", error_code="invalid_key"
        ) from exc
    return alg


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def parse_jwt(token):
    try:
        decoded = _JWS.decode_complete(token, options={"verify_signature": False})
        header = json.loads(
            jwt.utils.base64url_decode(token.split(".")[0]), object_pairs_hook=_object
        )
        payload = json.loads(decoded["payload"], object_pairs_hook=_object)
        if not isinstance(payload, dict) or not isinstance(header, dict):
            raise ValueError("JWT must contain JSON objects")
        return header, payload
    except Exception as exc:
        raise TokenError("Cannot decode JWT", error_code="invalid_jwt") from exc


def encode_jwt(payload, private_key, kid, typ):
    alg = public_key_to_jwk(private_key.public_key())["alg"]
    return _JWS.encode(
        json.dumps(payload, separators=(",", ":"), allow_nan=False).encode(),
        private_key,
        algorithm=alg,
        headers={"typ": typ, "kid": kid},
    )


def verify_jwt(token, jwks, *, require_times=True):
    header, payload = parse_jwt(token)
    alg = header.get("alg")
    if alg not in _ALGS:
        raise TokenError(
            "Unsupported JWT algorithm", error_code="unsupported_algorithm"
        )
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenError("JWT missing kid", error_code="invalid_jwt")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise TokenError("Invalid JWKS", error_code="unknown_key")
    # Inspect only the selected key, allowing unrelated algorithms in the JWKS.
    keys = [
        k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kid") == kid
    ]
    if len(keys) != 1:
        raise TokenError("Missing or ambiguous issuer key", error_code="unknown_key")
    key = keys[0]
    return verify_embedded_jwt(token, key, require_times=require_times)


def verify_embedded_jwt(token, key, *, require_times=True):
    header, payload = parse_jwt(token)
    alg = header.get("alg")
    validate_algorithm(key, alg)
    if alg not in _ALGS:
        raise TokenError(
            "Unsupported JWT algorithm", error_code="unsupported_algorithm"
        )
    try:
        _JWS.decode(token, jwk_to_public_key(key), algorithms=[alg])
    except Exception as exc:
        raise TokenError(
            "JWT signature verification failed", error_code="invalid_jwt"
        ) from exc
    if require_times:
        for name in ("iat", "exp"):
            value = payload.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise TokenError(
                    f"JWT missing or invalid {name}", error_code="invalid_jwt"
                )
        if payload["exp"] <= time.time():
            raise TokenError("Token has expired", error_code="expired_jwt")
        if payload["exp"] <= payload["iat"]:
            raise TokenError("Invalid token lifetime", error_code="invalid_jwt")
    return payload


def validate_server_identifier(value):
    from urllib.parse import urlsplit

    try:
        u = urlsplit(value)
        if (
            not isinstance(value, str)
            or u.scheme != "https"
            or not u.hostname
            or u.netloc != u.hostname
            or u.port is not None
            or u.path
            or u.query
            or u.fragment
            or value != value.lower()
            or not value.isascii()
        ):
            raise ValueError(
                "Expected lowercase HTTPS origin without port, path, query, or fragment"
            )
    except Exception as exc:
        raise TokenError("Invalid server identifier", error_code="invalid_jwt") from exc
    return value


def validate_agent_identifier(value):
    import re

    if not isinstance(value, str) or not re.fullmatch(
        r"aauth:[A-Za-z0-9_+.\-]{1,255}@[a-z0-9](?:[a-z0-9.\-]*[a-z0-9])?", value
    ):
        raise TokenError("Invalid agent identifier", error_code="invalid_jwt")
    return value


def verify_agent_claims(token, jwks_fetcher, expected_aud=None):
    header, p = parse_jwt(token)
    if header.get("typ") != "aa-agent+jwt" or p.get("dwk") != "aauth-agent.json":
        raise TokenError(
            "Invalid agent token type or dwk",
            token_type="aa-agent+jwt",
            error_code="invalid_jwt",
        )
    validate_server_identifier(p.get("iss"))
    validate_agent_identifier(p.get("sub"))
    if not isinstance(p.get("jti"), str) or not p["jti"]:
        raise TokenError("Agent token missing jti", error_code="invalid_jwt")
    if "ps" in p:
        validate_server_identifier(p["ps"])
    if "parent_agent" in p:
        validate_agent_identifier(p["parent_agent"])
        if p["parent_agent"] == p["sub"]:
            raise TokenError(
                "Sub-agent cannot name itself as parent", error_code="invalid_jwt"
            )
    from ..verifier import _fetch_jwks

    p = verify_jwt(
        token, _fetch_jwks(jwks_fetcher, p["iss"], p["dwk"], header.get("kid")) or {}
    )
    cnf = p.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise TokenError("Missing cnf.jwk", error_code="invalid_jwt")
    validate_algorithm(cnf["jwk"])
    if (
        "aud" in p
        and expected_aud
        and expected_aud not in (p["aud"] if isinstance(p["aud"], list) else [p["aud"]])
    ):
        raise TokenError("Agent token audience mismatch", error_code="invalid_jwt")
    return p
