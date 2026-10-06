"""Resource authentication and request-context binding for draft -11."""

from urllib.parse import urlsplit
from ..signing.verifier import verify_signature
from ..signing.signature_key import parse_signature_key
from ..tokens.common import verify_token, parse_jwt, check_server
from ..keys.jwk import calculate_jwk_thumbprint
from ..errors import AAuthError, SignatureError, TokenError
from ..headers.aauth_header import parse_authorization_aauth_header


class RequestVerifier:
    def __init__(
        self,
        canonical_authorities,
        jwks_fetcher=None,
        trusted_auth_servers=None,
        *,
        resource_id=None,
        trusted_person_servers=None,
        session_token_verifier=None,
        additional_signature_components=None,
        signature_window=60,
        revocation_checker=None,
    ):
        self.canonical_authorities = canonical_authorities
        self.jwks_fetcher = jwks_fetcher
        self.resource_id = check_server(resource_id) if resource_id else None
        self.trusted_auth_servers = frozenset(trusted_auth_servers or [])
        self.trusted_person_servers = frozenset(
            trusted_person_servers or trusted_auth_servers or []
        )
        self.session_token_verifier = session_token_verifier
        self.additional_signature_components = additional_signature_components or []
        self.signature_window = signature_window
        self.revocation_checker = revocation_checker

    def verify_request(
        self,
        method,
        target_uri,
        headers,
        body=None,
        require_identity=False,
        require_auth_token=False,
        *,
        require_person_token=False,
        require_session_token=False,
        required_scopes=None,
    ):
        try:
            h = {k.lower(): v for k, v in headers.items()}
            u = urlsplit(target_uri)
            if u.netloc not in self.canonical_authorities:
                raise TokenError("Request authority is not canonical")
            resource = self.resource_id or check_server(u.scheme + "://" + u.netloc)
            key = parse_signature_key(h.get("signature-key", ""))
            if key["scheme"] != "jwt":
                raise SignatureError(
                    "AAuth agents must use jwt", error_code="unsupported_scheme"
                )
            tok = key["params"].get("jwt")
            header, unverified = parse_jwt(tok)
            typ = header.get("typ")
            if typ not in ("aa-agent+jwt", "aa-person+jwt", "aa-auth+jwt"):
                raise TokenError(
                    "Unexpected request token type", error_code="invalid_jwt"
                )
            if (
                typ == "aa-auth+jwt"
                and unverified.get("iss") not in self.trusted_auth_servers
            ):
                raise TokenError(
                    "Untrusted auth token issuer", error_code="invalid_jwt"
                )
            if (
                typ == "aa-person+jwt"
                and unverified.get("iss") not in self.trusted_person_servers
            ):
                raise TokenError(
                    "Untrusted person token issuer", error_code="invalid_jwt"
                )
            if not self.jwks_fetcher:
                raise TokenError("JWKS fetcher is required")
            required = [
                "@method",
                "@authority",
                "@path",
                "signature-key",
                *self.additional_signature_components,
            ]
            if not verify_signature(
                method,
                target_uri,
                headers,
                body,
                h.get("signature-input", ""),
                h.get("signature", ""),
                h.get("signature-key", ""),
                jwks_fetcher=self.jwks_fetcher,
                required_components=required,
                signature_window=self.signature_window,
            ):
                raise SignatureError("Signature verification failed")
            p = verify_token(
                tok,
                self.jwks_fetcher,
                expected_typ=typ,
                expected_aud=resource,
                revocation_checker=self.revocation_checker,
            )
            if require_auth_token and typ != "aa-auth+jwt":
                raise TokenError("Auth token required")
            if require_person_token and typ != "aa-person+jwt":
                raise TokenError("Person token required")
            if require_identity and typ != "aa-agent+jwt":
                raise TokenError("Agent token required for agent identity")
            scopes = p.get("scope", "").split()
            if required_scopes and not set(required_scopes).issubset(scopes):
                return {
                    "valid": False,
                    "error": "Insufficient scope",
                    "error_code": "insufficient_scope",
                }
            session = parse_authorization_aauth_header(h.get("authorization", ""))
            if require_session_token and not session:
                raise TokenError("Session token required")
            if session and (
                not self.session_token_verifier
                or not self.session_token_verifier(
                    session, calculate_jwk_thumbprint(p["cnf"]["jwk"])
                )
            ):
                raise TokenError("Invalid or unbound session token")
            return {
                "valid": True,
                "token_type": typ,
                "claims": p,
                "agent_id": p["sub"] if typ == "aa-agent+jwt" else None,
                "user_sub": p["sub"] if typ != "aa-agent+jwt" else None,
                "person_server": (
                    p.get("ps", p["iss"]) if typ != "aa-agent+jwt" else p.get("ps")
                ),
                "scopes": scopes,
                "act": None,
                "session_token": session,
            }
        except (AAuthError, ValueError, TypeError, KeyError) as exc:
            return {
                "valid": False,
                "error": str(exc),
                "error_code": getattr(exc, "error_code", None) or "invalid_jwt",
            }
