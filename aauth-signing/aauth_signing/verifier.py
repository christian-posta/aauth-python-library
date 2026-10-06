"""HTTP signature verification per RFC 9421 and draft-hardt-httpbis-signature-key-04."""

import re
import time
import logging
import hashlib
import base64
import json
from typing import Dict, Any, Optional, Callable
from urllib.parse import urlparse
import jwt as pyjwt
from .signature_key import parse_signature_key
from .signature_input import parse_signature_input
from .signature import parse_signature
from .signature_base import build_signature_base
from .keys.jwk import jwk_to_public_key, calculate_jwk_thumbprint
from .errors import SignatureError, TokenError
from .tokens.common import parse_jwt, verify_jwt, validate_algorithm


def verify_signature(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    signature_input_header: str,
    signature_header: str,
    signature_key_header: str,
    public_key=None,
    jwks_fetcher: Optional[Callable] = None,
    required_components=None,
    signature_window: int = 60,
) -> bool:
    """Verify HTTP signature using HTTP Message Signatures (RFC 9421).

    The jwks_fetcher callback is used for key discovery. Its signature depends
    on the Signature-Key scheme:

    - For ``jwks_uri``: called as ``jwks_fetcher(id, dwk, kid)`` where *id* is
      the signer identifier, *dwk* the well-known metadata document name, and
      *kid* the key identifier. The fetcher SHOULD perform two-step discovery:
      fetch ``{id}/.well-known/{dwk}``, extract ``jwks_uri``, fetch the JWKS,
      and return the full JWKS dict.
    - For ``jwt``: called as ``jwks_fetcher(iss, dwk, kid)`` using the JWT's
      ``iss``, ``dwk``, and header ``kid`` claims.

    For backward compatibility the fetcher MAY also accept a single positional
    argument (the identifier) — the verifier will fall back to that form.

    Args:
        method: HTTP method
        target_uri: Target URI
        headers: Request headers
        body: Request body bytes (None if no body)
        signature_input_header: Signature-Input header value
        signature_header: Signature header value
        signature_key_header: Signature-Key header value
        public_key: Optional public key (for hwk scheme)
        jwks_fetcher: Optional JWKS fetcher function (for jwks_uri/jwt/jkt-jwt schemes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        SignatureError: If verification fails due to invalid format
    """
    logger = logging.getLogger("aauth_signing")

    logger.debug("VERIFIER: verify_signature() called")
    logger.debug(f"VERIFIER: method={method}, target_uri={target_uri}")
    logger.debug(f"VERIFIER: signature_input_header={signature_input_header}")

    try:
        # Parse Signature-Input
        components, sig_params = parse_signature_input(signature_input_header)

        required = set(
            required_components or ["@method", "@authority", "@path", "signature-key"]
        )
        if any(k.lower() == "authorization" for k in headers):
            required.add("authorization")
        if not required.issubset(components):
            raise SignatureError(
                "Missing required covered components",
                error_code="invalid_input",
                details={"required_input": sorted(required)},
            )
        created = sig_params.get("created")
        if type(created) is not int:
            return False
        now = time.time()
        if created > now + signature_window:
            raise SignatureError(
                "Signature created is in the future", error_code="clock_skew"
            )
        if created < now - signature_window:
            return False
        if "expires" in sig_params:
            expires = sig_params["expires"]
            if type(expires) is not int or expires <= now or expires < created:
                return False
        if "content-digest" in components and not _verify_content_digest(headers, body):
            return False

        # Parse Signature-Key
        parsed_key = parse_signature_key(signature_key_header)
        scheme = parsed_key["scheme"]
        params = parsed_key["params"]
        label = parsed_key["label"]

        # Verify label consistency across all three headers (SIG-KEY §3.1)
        label_match = re.match(r"(\w+)=", signature_input_header)
        sig_label_match = re.match(r"(\w+)=", signature_header)

        if not (label_match and sig_label_match):
            return False

        if not (label_match.group(1) == sig_label_match.group(1) == label):
            return False

        # --- Extract public key based on scheme ---

        if scheme == "hwk":
            jwk = {
                name: params[name]
                for name in ("kty", "crv", "x", "y", "n", "e", "alg")
                if name in params
            }
            validate_algorithm(jwk)
            discovered_key = jwk_to_public_key(jwk)
            if public_key is not None:
                from .keys.jwk import public_key_to_jwk

                if calculate_jwk_thumbprint(
                    public_key_to_jwk(public_key)
                ) != calculate_jwk_thumbprint(jwk):
                    return False
            public_key = discovered_key

        elif scheme == "jwks_uri":
            # SIG-KEY §3.5: JWKS URI Discovery
            # Parameters: id (REQUIRED), dwk (REQUIRED), kid (REQUIRED)
            if not jwks_fetcher:
                raise SignatureError("scheme=jwks_uri requires jwks_fetcher")

            agent_id = params.get("id")
            dwk = params.get("dwk")
            kid = params.get("kid")

            if not agent_id:
                raise SignatureError("scheme=jwks_uri: missing required 'id' parameter")
            if not dwk:
                raise SignatureError(
                    "scheme=jwks_uri: missing required 'dwk' parameter"
                )
            if not kid:
                raise SignatureError(
                    "scheme=jwks_uri: missing required 'kid' parameter"
                )

            # Fetch JWKS via two-step discovery: {id}/.well-known/{dwk} -> jwks_uri -> JWKS
            jwks = _fetch_jwks(jwks_fetcher, agent_id, dwk, kid)
            if not jwks:
                return False

            # Find key by kid
            signing_key = _find_key_by_kid(jwks, kid)
            if not signing_key:
                return False

            validate_algorithm(signing_key)
            public_key = jwk_to_public_key(signing_key)

        elif scheme == "jkt-jwt":
            # SIG-KEY §3.4: JKT JWT Self-Issued Key Delegation
            public_key = _verify_jkt_jwt_scheme(params, logger)
            if public_key is None:
                return False

        elif scheme == "jwt":
            # SIG-KEY §3.6: JWT Confirmation Key
            # Generic JWT scheme — extract cnf.jwk from any JWT with cnf claim.
            # AAuth-specific type validation (aa-agent+jwt, aa-auth+jwt) is done
            # at the protocol layer (aauth/resource/verifier.py), not here.
            if not jwks_fetcher:
                raise SignatureError("scheme=jwt requires jwks_fetcher")

            jwt_token = params.get("jwt")
            if not jwt_token:
                return False

            public_key = _verify_jwt_scheme(jwt_token, jwks_fetcher, logger)
            if public_key is None:
                return False

        elif scheme == "x509":
            # SIG-KEY §3.7: X.509 Certificates
            # Not yet implemented — would require certificate chain validation
            raise SignatureError("scheme=x509 is not yet implemented")

        else:
            raise SignatureError(f"Unknown signature scheme: {scheme}")

        if "keyid" in sig_params:
            if scheme == "jwks_uri":
                candidates = {params.get("kid")}
            elif scheme == "hwk":
                candidates = {calculate_jwk_thumbprint(jwk)}
            else:
                _, token_claims = parse_jwt(params["jwt"])
                confirmation = token_claims["cnf"]["jwk"]
                candidates = {
                    confirmation.get("kid"),
                    calculate_jwk_thumbprint(confirmation),
                }
            if sig_params["keyid"] not in candidates:
                raise SignatureError(
                    "keyid disagrees with Signature-Key", error_code="invalid_key"
                )

        # Reconstruct signature base
        parsed_uri = urlparse(target_uri)
        authority = parsed_uri.netloc
        path = parsed_uri.path or "/"
        query_string = parsed_uri.query if parsed_uri.query else None

        # Extract signature params (the part after "{label}=") for @signature-params line
        prefix = f"{label}="
        if signature_input_header.startswith(prefix):
            signature_params = signature_input_header[len(prefix) :]
        else:
            signature_params = signature_input_header
        if not signature_params:
            return False

        logger.debug(f"VERIFIER: Building signature base")
        logger.debug(f"VERIFIER: method={method}, authority={authority}, path={path}")
        logger.debug(f"VERIFIER: covered_components={components}")

        signature_base = build_signature_base(
            method=method,
            authority=authority,
            path=path,
            query=query_string,
            headers=headers,
            body=body,
            signature_key_header=signature_key_header,
            covered_components=components,
            signature_params=signature_params,
        )

        logger.debug(f"VERIFIER: Signature base length: {len(signature_base)} bytes")

        # Parse signature
        signature_bytes = parse_signature(signature_header, label=label)

        # Verify signature
        try:
            _verify_with_key(
                public_key, signature_bytes, signature_base.encode("utf-8")
            )
            logger.debug("VERIFIER: Signature verification PASSED")
            return True
        except Exception as e:
            logger.debug(f"VERIFIER: Signature verification FAILED: {e}")
            return False

    except TokenError as exc:
        raise SignatureError(
            str(exc), error_code=exc.error_code or "invalid_jwt"
        ) from exc
    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(f"Signature verification failed: {e}") from e


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch_jwks(
    jwks_fetcher: Callable,
    identifier: str,
    dwk: str,
    kid: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Call jwks_fetcher with the best calling convention available.

    Tries ``jwks_fetcher(identifier, dwk, kid)`` first. If the fetcher does
    not accept three arguments, falls back to ``jwks_fetcher(identifier, dwk)``
    then ``jwks_fetcher(identifier)``.
    """
    if not callable(jwks_fetcher):
        return jwks_fetcher  # type: ignore[return-value]

    # Try 3-arg form first (id, dwk, kid)
    try:
        result = jwks_fetcher(identifier, dwk, kid)
        return result
    except TypeError:
        pass

    # Try 2-arg form (id, dwk)
    try:
        result = jwks_fetcher(identifier, dwk)
        return result
    except TypeError:
        pass

    # Fall back to 1-arg (id) for backward compat
    try:
        result = jwks_fetcher(identifier)
        return result
    except Exception:
        return None


def _find_key_by_kid(jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
    """Find a key in a JWKS by kid."""
    keys = jwks.get("keys", [])
    for key in keys:
        if key.get("kid") == kid:
            return key
    return None


def _verify_jkt_jwt_scheme(params: Dict[str, str], logger) -> Any:
    """Verify jkt-jwt scheme per SIG-KEY §3.4.

    Returns the ephemeral public key from cnf.jwk, or None on failure.
    """
    jwt_token = params.get("jwt")
    if not jwt_token:
        logger.debug("VERIFIER: jkt-jwt scheme missing 'jwt' parameter")
        return None

    try:
        # Step 1: Parse JWT without verifying
        header = pyjwt.get_unverified_header(jwt_token)
        payload = pyjwt.decode(jwt_token, options={"verify_signature": False})
    except Exception as e:
        logger.debug(f"VERIFIER: jkt-jwt JWT parse failed: {e}")
        return None

    # Step 2: Check typ header (jkt-s256+jwt or jkt-s512+jwt)
    typ = header.get("typ", "")
    typ_to_hash = {
        "jkt-s256+jwt": ("sha-256", hashlib.sha256),
        "jkt-s512+jwt": ("sha-512", hashlib.sha512),
    }
    if typ not in typ_to_hash:
        logger.debug(f"VERIFIER: jkt-jwt unsupported typ: {typ}")
        return None

    hash_name, hash_fn = typ_to_hash[typ]

    # Step 3-4: Extract jwk from JWT header
    header_jwk = header.get("jwk")
    if not header_jwk:
        logger.debug("VERIFIER: jkt-jwt header missing 'jwk'")
        return None

    # Step 5: Compute JWK Thumbprint of header jwk using the determined hash
    thumbprint = _compute_jwk_thumbprint(header_jwk, hash_fn)

    # Step 6: Construct expected iss
    expected_iss = f"urn:jkt:{hash_name}:{thumbprint}"

    # Step 7: Verify iss matches
    iss = payload.get("iss")
    if iss != expected_iss:
        logger.debug(
            f"VERIFIER: jkt-jwt iss mismatch: expected {expected_iss}, got {iss}"
        )
        return None

    from .tokens.common import verify_embedded_jwt

    try:
        payload = verify_embedded_jwt(jwt_token, header_jwk)
    except TokenError:
        return None

    # Step 10: Extract ephemeral public key from cnf.jwk
    cnf = payload.get("cnf")
    if not cnf or not cnf.get("jwk"):
        logger.debug("VERIFIER: jkt-jwt missing cnf.jwk")
        return None

    # Step 11: Return the ephemeral key — caller verifies HTTP sig with it
    try:
        validate_algorithm(cnf["jwk"])
        return jwk_to_public_key(cnf["jwk"])
    except Exception as e:
        logger.debug(f"VERIFIER: jkt-jwt cnf.jwk conversion failed: {e}")
        return None


def _compute_jwk_thumbprint(jwk_dict: Dict[str, Any], hash_fn) -> str:
    """Compute JWK Thumbprint per RFC 7638 using a given hash function.

    Args:
        jwk_dict: JWK as a dictionary
        hash_fn: Hash function (e.g. hashlib.sha256)

    Returns:
        Base64url-encoded thumbprint (no padding)
    """
    kty = jwk_dict.get("kty", "")

    # Build canonical JWK per RFC 7638 §3.2 (sorted required members only)
    if kty == "OKP":
        canonical = {"crv": jwk_dict["crv"], "kty": kty, "x": jwk_dict["x"]}
    elif kty == "EC":
        canonical = {
            "crv": jwk_dict["crv"],
            "kty": kty,
            "x": jwk_dict["x"],
            "y": jwk_dict["y"],
        }
    elif kty == "RSA":
        canonical = {"e": jwk_dict["e"], "kty": kty, "n": jwk_dict["n"]}
    else:
        raise ValueError(f"Unsupported kty for thumbprint: {kty}")

    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hash_fn(canonical_json.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _verify_jwt_scheme(jwt_token, jwks_fetcher, logger):
    header, payload = parse_jwt(jwt_token)
    iss, dwk = payload.get("iss"), payload.get("dwk")
    if not isinstance(iss, str) or not iss or not isinstance(dwk, str) or not dwk:
        raise TokenError("JWT missing issuer or dwk", error_code="invalid_jwt")
    jwks = _fetch_jwks(jwks_fetcher, iss, dwk, header.get("kid"))
    if not jwks:
        raise TokenError("Issuer JWKS unavailable", error_code="unknown_key")
    payload = verify_jwt(jwt_token, jwks)
    cnf = payload.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise TokenError("JWT missing cnf.jwk", error_code="invalid_jwt")
    validate_algorithm(cnf["jwk"])
    return jwk_to_public_key(cnf["jwk"])


def _verify_content_digest(headers, body):
    import hmac
    import http_sfv

    value = next((v for k, v in headers.items() if k.lower() == "content-digest"), None)
    if not value or body is None:
        return False
    try:
        fields = http_sfv.Dictionary()
        fields.parse(value.encode("ascii"))
        checked = False
        for alg, item in fields.items():
            if alg not in ("sha-256", "sha-512"):
                continue
            digest = (
                hashlib.sha256(body).digest()
                if alg == "sha-256"
                else hashlib.sha512(body).digest()
            )
            if not isinstance(item.value, bytes) or not hmac.compare_digest(
                item.value, digest
            ):
                return False
            checked = True
        return checked
    except Exception:
        return False


def _p1363_to_der(sig: bytes) -> bytes:
    """Convert IEEE P1363 ECDSA signature (r||s) to DER (ASN.1 SEQUENCE)."""
    half = len(sig) // 2
    r = int.from_bytes(sig[:half], "big")
    s = int.from_bytes(sig[half:], "big")

    def _encode_int(n: int) -> bytes:
        raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    inner = r_enc + s_enc
    return b"\x30" + bytes([len(inner)]) + inner


def _verify_with_key(public_key, signature_bytes: bytes, message: bytes) -> None:
    """Verify a signature, dispatching to the right algorithm for the key type.

    Raises on failure (same semantics as the underlying cryptography verify calls).
    Supports Ed25519 and EC (P-256, P-384) keys.  For EC keys, both DER and
    IEEE P1363 (raw r||s) signature formats are accepted to interoperate with
    implementations that use the Web Crypto API (which produces P1363).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
        ECDSA,
        SECP256R1,
        SECP384R1,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    if isinstance(public_key, Ed25519PublicKey):
        public_key.verify(signature_bytes, message)
        return

    if isinstance(public_key, EllipticCurvePublicKey):
        curve = public_key.curve
        if isinstance(curve, SECP384R1):
            hash_alg = hashes.SHA384()
        else:
            hash_alg = hashes.SHA256()

        # Try the signature as-is first (DER, which is what the cryptography
        # library produces), then fall back to treating it as IEEE P1363
        # (raw r||s, produced by the Web Crypto API / Jose / JWT libraries).
        last_exc: Exception = InvalidSignature("empty")
        for sig in (signature_bytes, _p1363_to_der(signature_bytes)):
            try:
                public_key.verify(sig, message, ECDSA(hash_alg))
                return
            except Exception as exc:
                last_exc = exc
        raise last_exc

    raise ValueError(f"Unsupported public key type: {type(public_key)}")
