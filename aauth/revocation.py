"""Issuer-scoped revocation state, cascades, and signed revocation requests.

The in-memory store is suitable for tests and a single process. Applications
must retain these records in shared durable storage in multi-worker deployments.
"""

import json
import time
from dataclasses import dataclass, field
from .signing.signer import sign_request
from .signing.verifier import verify_signature
from .signing.signature_key import parse_signature_key
from .tokens.common import check_server
from .errors import TokenError, SignatureError
from .http.response import AAuthResponse
from .agent.poller import async_poll_pending_url, pending_location


def revocation_body(jti, exp):
    if not isinstance(jti, str) or not jti or type(exp) is not int:
        raise TokenError(
            "Revocation requires nonempty jti and integer exp",
            error_code="invalid_request",
        )
    return {"jti": jti, "exp": exp}


def sign_revocation_request(endpoint, jti, exp, private_key, issuer, kid, dwk):
    check_server(issuer)
    body = json.dumps(revocation_body(jti, exp), separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    headers.update(
        sign_request(
            "POST",
            endpoint,
            headers,
            body,
            private_key,
            sig_scheme="jwks_uri",
            id=issuer,
            kid=kid,
            dwk=dwk,
            additional_signature_components=["content-digest", "content-type"],
        )
    )
    return headers, body


async def send_revocation(
    endpoint, jti, exp, private_key, issuer, kid, dwk, *, http_client=None, max_polls=60
):
    if not endpoint:
        return {"error": "revocation_unsupported"}
    if http_client is None:
        import httpx
        from .keys.jwks import AdmittedHTTPClient

        async with httpx.AsyncClient(timeout=30) as client:
            return await send_revocation(
                endpoint,
                jti,
                exp,
                private_key,
                issuer,
                kid,
                dwk,
                http_client=AdmittedHTTPClient(client),
                max_polls=max_polls,
            )
    try:
        headers, body = sign_revocation_request(
            endpoint, jti, exp, private_key, issuer, kid, dwk
        )
        response = await http_client.post(endpoint, headers=headers, content=body)
        if response.status_code == 202:
            location = pending_location(response.headers.get("location"), endpoint)

            async def get(url):
                headers = sign_request(
                    "GET",
                    url,
                    {},
                    None,
                    private_key,
                    sig_scheme="jwks_uri",
                    id=issuer,
                    kid=kid,
                    dwk=dwk,
                )
                return await http_client.get(url, headers=headers)

            result = await async_poll_pending_url(
                location, get, initial_response=response, max_polls=max_polls
            )
            if not result.success:
                return {"error": "revocation_unavailable"}
            response = result.response
        if (
            response.status_code == 403
            and response.json().get("error") == "unsupported_iss"
        ):
            return {"error": "revocation_unsupported"}
        if response.status_code != 200:
            return {"error": "revocation_unavailable"}
        if not response.content:
            return {}
        if response.headers.get("content-type", "").split(";")[0] != "application/json":
            return {"error": "revocation_unavailable"}
        data = response.json()
        if not isinstance(data, dict):
            return {"error": "revocation_unavailable"}
        if "downstream" in data and (
            not isinstance(data["downstream"], list)
            or any(
                not isinstance(x, dict)
                or not isinstance(x.get("recipient"), str)
                or x.get("error")
                not in (None, "revocation_unsupported", "revocation_unavailable")
                for x in data["downstream"]
            )
        ):
            return {"error": "revocation_unavailable"}
        return data
    except Exception:
        return {"error": "revocation_unavailable"}


@dataclass
class IssuedToken:
    issuer: str
    jti: str
    exp: int
    recipients: tuple
    dependencies: tuple = ()
    agent_identity: tuple = None
    mission_s256: str = None
    outcomes: dict = field(default_factory=dict)


class RevocationStore:
    """Replaceable state container; keys include issuer, never jti alone."""

    def __init__(self):
        self.revoked = {}
        self.issued = {}
        self.agents = {}

    def is_revoked(self, issuer, jti):
        exp = self.revoked.get((issuer, jti))
        if exp is None:
            return False
        if time.time() > exp:
            self.revoked.pop((issuer, jti), None)
            return False
        return True

    def record(self, issuer, jti, exp):
        check_server(issuer)
        revocation_body(jti, exp)
        self.revoked[(issuer, jti)] = max(exp, self.revoked.get((issuer, jti), exp))

    def record_agent(self, claims):
        self.agents[(claims["iss"], claims["jti"])] = (
            claims["iss"],
            claims["sub"],
            claims["exp"],
        )

    def record_issued(
        self, claims, recipients, *, dependencies=(), agent_identity=None
    ):
        key = (claims["iss"], claims["jti"])
        self.issued[key] = IssuedToken(
            *key,
            claims["exp"],
            tuple(recipients),
            tuple(dependencies),
            agent_identity,
            claims.get("mission_s256"),
        )


class RevocationManager:
    """Record before sending; wait until downstream outcomes are terminal.

    send(recipient, jti, exp) is an async application callback, normally backed
    by send_revocation(). A PS returns an empty body; an AS reports downstream.
    """

    def __init__(
        self, issuer, role, store, send, allowed_issuers, *, max_lifetime=86400
    ):
        self.issuer = check_server(issuer)
        self.role = role
        self.store = store
        self.send = send
        self.allowed_issuers = frozenset(allowed_issuers)
        self.max_lifetime = max_lifetime

    async def revoke(self, issuer, jti, exp):
        revocation_body(jti, exp)
        if issuer not in self.allowed_issuers:
            raise TokenError(
                "Revocations from issuer are not accepted", error_code="unsupported_iss"
            )
        if exp > time.time() + self.max_lifetime:
            raise TokenError(
                "Revocation expiration exceeds accepted lifetime",
                error_code="invalid_request",
            )
        self.store.record(issuer, jti, exp)
        agent = self.store.agents.get((issuer, jti)) if self.role == "ps" else None
        queue = [(issuer, jti)]
        visited = set()
        scheduled = {(issuer, jti)}
        report = []
        while queue:
            key = queue.pop(0)
            if key in visited:
                continue
            visited.add(key)
            for child_key, node in list(self.store.issued.items()):
                if node.exp <= time.time():
                    continue
                if key in node.dependencies or (
                    agent and node.agent_identity == agent[:2]
                ):
                    if child_key in scheduled:
                        continue
                    self.store.record(*child_key, node.exp)
                    scheduled.add(child_key)
                    queue.append(child_key)
                    for recipient in node.recipients:
                        if node.outcomes.get(recipient) == {}:
                            continue
                        try:
                            outcome = await self.send(recipient, node.jti, node.exp)
                        except Exception:
                            outcome = {"error": "revocation_unavailable"}
                        if not isinstance(outcome, dict) or outcome.get(
                            "error"
                        ) not in (
                            None,
                            "revocation_unsupported",
                            "revocation_unavailable",
                        ):
                            outcome = {"error": "revocation_unavailable"}
                        node.outcomes[recipient] = outcome
                        report.append(
                            {
                                "recipient": recipient,
                                **(
                                    {"error": outcome["error"]}
                                    if outcome.get("error")
                                    else {}
                                ),
                            }
                        )
                    # Report prior successes on a repeat too.
                    for recipient in node.recipients:
                        if node.outcomes.get(recipient) == {} and not any(
                            x["recipient"] == recipient for x in report
                        ):
                            report.append({"recipient": recipient})
        return {"downstream": report} if self.role == "as" and report else {}

    async def handle_request(self, method, target_uri, headers, body, jwks_fetcher):
        h = {k.lower(): v for k, v in headers.items()}
        try:
            key = parse_signature_key(h.get("signature-key", ""))
            if method != "POST" or key["scheme"] != "jwks_uri":
                raise SignatureError(
                    "Revocations require a signed server POST",
                    error_code="unsupported_scheme",
                )
            issuer = check_server(key["params"].get("id"))
            if key["params"].get("dwk") not in (
                "aauth-agent.json",
                "aauth-person.json",
                "aauth-access.json",
                "aauth-resource.json",
            ):
                raise SignatureError(
                    "Invalid server metadata document", error_code="invalid_key"
                )
            required = [
                "@method",
                "@authority",
                "@path",
                "signature-key",
                "content-digest",
                "content-type",
            ]
            valid = verify_signature(
                method,
                target_uri,
                headers,
                body,
                h.get("signature-input", ""),
                h.get("signature", ""),
                h.get("signature-key", ""),
                jwks_fetcher=jwks_fetcher,
                required_components=required,
            )
            if not valid:
                raise SignatureError("Invalid revocation signature")
        except (SignatureError, TokenError, ValueError) as exc:
            return AAuthResponse(
                401,
                {
                    "Signature-Error": "error="
                    + (getattr(exc, "error_code", None) or "invalid_signature")
                },
            )
        try:
            if h.get("content-type", "").split(";")[0] != "application/json":
                raise TokenError(
                    "Expected application/json", error_code="invalid_request"
                )
            try:
                params = json.loads(body)
            except Exception:
                raise TokenError("Malformed JSON", error_code="invalid_request")
            if not isinstance(params, dict) or set(params) != {"jti", "exp"}:
                raise TokenError("Expected jti and exp", error_code="invalid_request")
            result = await self.revoke(issuer, params["jti"], params["exp"])
            return AAuthResponse(
                200,
                {"Content-Type": "application/json"} if result else {},
                json.dumps(result).encode() if result else None,
            )
        except TokenError as exc:
            code = exc.error_code or "invalid_request"
            return AAuthResponse(
                403 if code == "unsupported_iss" else 400,
                {"Content-Type": "application/problem+json"},
                json.dumps({"error": code, "detail": str(exc)}).encode(),
            )
