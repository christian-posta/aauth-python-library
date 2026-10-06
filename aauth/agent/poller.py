"""Shared sync/async deferred-response state machine for draft -11."""

import asyncio
import time
from urllib.parse import urljoin, urlsplit, urlencode
from ..headers.aauth_header import parse_aauth_header
from ..errors import TokenError


class PollingResult:
    def __init__(
        self,
        success,
        auth_token=None,
        response_body=None,
        status_code=0,
        error=None,
        error_description=None,
        require=None,
        code=None,
        response=None,
    ):
        self.success = success
        self.auth_token = auth_token
        self.response_body = response_body
        self.status_code = status_code
        self.error = error
        self.error_description = error_description
        self.require = require
        self.code = code
        self.response = response


def pending_location(location, base):
    if not isinstance(location, str) or not location:
        raise TokenError("202 response has no Location header")
    target = urljoin(base, location)
    a, b = urlsplit(base), urlsplit(target)
    origin = lambda u: (
        u.scheme,
        u.hostname,
        u.port or (443 if u.scheme == "https" else 80),
    )
    if origin(a) != origin(b) or b.username or b.password or b.fragment:
        raise TokenError("Pending Location must remain on the same origin")
    return target


def _body(response):
    try:
        value = response.json()
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _wait(headers, default):
    try:
        value = int(headers.get("retry-after", default))
        return max(value, 0)
    except (ValueError, TypeError):
        return default


def _steps(
    pending_url,
    max_polls,
    default_wait,
    initial_response,
    interaction_enabled,
    clarify_enabled,
):
    """Yield I/O operations; limit GET polls and clarification POSTs together."""
    prompted = set()
    response = initial_response
    count = 0
    while True:
        if response is None:
            if count >= max_polls:
                return PollingResult(
                    False,
                    error="max_polls_exceeded",
                    error_description=f"Exceeded {max_polls} polls",
                )
            response = yield ("get", pending_url)
            count += 1
        status = response.status_code
        body = _body(response)
        headers = {str(k).lower(): v for k, v in response.headers.items()}
        if status == 429:
            default_wait += 5
            yield ("sleep", max(default_wait, _wait(headers, default_wait)))
        elif status == 503:
            yield ("sleep", _wait(headers, max(default_wait * 2, 1)))
        elif status != 202:
            success = 200 <= status < 400
            error = body.get("error") or {
                403: "denied",
                408: "expired",
                410: "invalid_code",
                500: "server_error",
            }.get(status, "unexpected_status")
            return PollingResult(
                success,
                auth_token=body.get("auth_token"),
                response_body=body,
                status_code=status,
                error=None if success else error,
                error_description=body.get("detail", body.get("error_description")),
                response=response,
            )
        else:
            if "location" in headers:
                pending_url = pending_location(headers["location"], pending_url)
            raw = headers.get("aauth-requirement", "")
            parsed = parse_aauth_header(raw) if raw else {}
            requirement = (
                parsed.get("requirement")
                or body.get("requirement")
                or body.get("require")
            )
            code = parsed.get("code") or body.get("code")
            if (
                requirement == "interaction"
                and code
                and interaction_enabled
                and body.get("status") != "interacting"
            ):
                endpoint = parsed.get("url")
                if endpoint:
                    u = urlsplit(endpoint)
                    if (
                        u.scheme != "https"
                        or u.query
                        or u.fragment
                        or u.username
                        or u.password
                    ):
                        raise TokenError("Invalid interaction URL")
                    endpoint += "?" + urlencode({"code": code})
                else:
                    endpoint = pending_url  # Read older body-mirrored responses.
                key = (endpoint, code)
                if key not in prompted:
                    yield ("interaction", endpoint, code)
                    prompted.add(key)
            if (
                requirement == "clarification"
                and body.get("clarification")
                and clarify_enabled
            ):
                answer = yield ("clarify", pending_url, body["clarification"])
                if answer is not None:
                    if count >= max_polls:
                        return PollingResult(
                            False,
                            error="max_polls_exceeded",
                            error_description=f"Exceeded {max_polls} polls/replies",
                        )
                    count += 1
                    reply = yield (
                        "post",
                        pending_url,
                        {
                            "action": "clarification_response",
                            "clarification_response": answer,
                        },
                    )
                    # POST can itself complete or deny the pending operation.
                    response = reply
                    continue
            yield ("sleep", _wait(headers, default_wait))
        response = None


def poll_pending_url(
    pending_url,
    sign_and_send_get,
    max_polls=60,
    default_wait=5,
    on_interaction=None,
    on_clarification=None,
    sign_and_send_post=None,
    initial_response=None,
):
    steps = _steps(
        pending_url,
        max_polls,
        default_wait,
        initial_response,
        bool(on_interaction),
        bool(on_clarification and sign_and_send_post),
    )
    value = None
    try:
        while True:
            event = steps.send(value)
            value = None
            op, *args = event
            if op == "get":
                value = sign_and_send_get(*args)
            elif op == "sleep":
                if args[0]:
                    time.sleep(args[0])
            elif op == "interaction":
                on_interaction(*args)
            elif op == "clarify":
                value = on_clarification(*args)
            elif op == "post":
                value = sign_and_send_post(*args)
    except StopIteration as done:
        return done.value
    except TokenError as exc:
        return PollingResult(
            False, error="invalid_response", error_description=str(exc)
        )
    except Exception as exc:
        return PollingResult(False, error="network_error", error_description=str(exc))


async def async_poll_pending_url(
    pending_url,
    sign_and_send_get,
    max_polls=60,
    default_wait=5,
    on_interaction=None,
    on_clarification=None,
    sign_and_send_post=None,
    initial_response=None,
):
    steps = _steps(
        pending_url,
        max_polls,
        default_wait,
        initial_response,
        bool(on_interaction),
        bool(on_clarification and sign_and_send_post),
    )
    value = None
    try:
        while True:
            event = steps.send(value)
            value = None
            op, *args = event
            if op == "get":
                value = await sign_and_send_get(*args)
            elif op == "sleep":
                if args[0]:
                    await asyncio.sleep(args[0])
            elif op == "interaction":
                await on_interaction(*args)
            elif op == "clarify":
                value = await on_clarification(*args)
            elif op == "post":
                value = await sign_and_send_post(*args)
    except StopIteration as done:
        return done.value
    except TokenError as exc:
        return PollingResult(
            False, error="invalid_response", error_description=str(exc)
        )
    except Exception as exc:
        return PollingResult(False, error="network_error", error_description=str(exc))


def cancel_pending_request(sign_and_send_delete, pending_url):
    return sign_and_send_delete(pending_url)
