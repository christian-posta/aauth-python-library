"""Draft -11 mission approval bytes and lifecycle request helpers."""

import base64
import hashlib
import hmac
import json
from .tokens.common import check_hash
from .errors import TokenError


def build_mission_approval(mission, *, capabilities=None, person_tokens=None):
    if (
        not isinstance(mission, dict)
        or "approver" in mission
        or "capabilities" in mission
    ):
        raise TokenError(
            "Mission blob must be an object without approver or capabilities"
        )
    blob = json.dumps(
        mission, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    enc = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    result = {"s256": enc(hashlib.sha256(blob).digest()), "mission": enc(blob)}
    if capabilities is not None:
        result["capabilities"] = capabilities
    if person_tokens is not None:
        result["person_tokens"] = person_tokens
    return result


def parse_mission_approval(response):
    try:
        check_hash(response["s256"])
        encoded = response["mission"]
        if not isinstance(encoded, str):
            raise ValueError()
        blob = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(blob).digest())
            .rstrip(b"=")
            .decode()
        )
        if not hmac.compare_digest(digest, response["s256"]):
            raise ValueError("Mission hash mismatch")
        mission = json.loads(blob)
        if (
            not isinstance(mission, dict)
            or "approver" in mission
            or "capabilities" in mission
        ):
            raise ValueError()
        return {
            "mission_s256": digest,
            "mission": mission,
            "blob": blob,
            "capabilities": response.get("capabilities", []),
            "person_tokens": response.get("person_tokens", {}),
        }
    except Exception as exc:
        raise TokenError("Invalid mission approval or hash") from exc


def mission_request(mission_endpoint, mission_s256, action, **params):
    from .identifiers import validate_endpoint_url

    validate_endpoint_url(mission_endpoint)
    check_hash(mission_s256)
    if action not in ("update", "completion"):
        raise TokenError("Unknown mission action")
    return mission_endpoint.rstrip("/") + "/" + mission_s256, dict(
        params, action=action
    )


def token_needs_refresh(claims, now=None, margin=300):
    import time

    return claims["exp"] - (time.time() if now is None else now) < margin
