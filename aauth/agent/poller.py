"""Polling state machine for deferred responses.

Per spec Section 10.6, the agent polls the pending URL with GET
until a terminal response is received.

This module provides a synchronous polling implementation for demos.
"""

import time
import logging
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger("aauth.agent.poller")


class PollingResult:
    """Result of polling a pending URL."""

    def __init__(
        self,
        success: bool,
        auth_token: Optional[str] = None,
        response_body: Optional[Dict[str, Any]] = None,
        status_code: int = 0,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
        require: Optional[str] = None,
        code: Optional[str] = None,
    ):
        self.success = success
        self.auth_token = auth_token
        self.response_body = response_body
        self.status_code = status_code
        self.error = error
        self.error_description = error_description
        self.require = require
        self.code = code


def poll_pending_url(
    pending_url: str,
    sign_and_send_get: Callable[[str], Any],
    max_polls: int = 60,
    default_wait: int = 2,
    on_interaction: Optional[Callable[[str, str], None]] = None,
    on_clarification: Optional[Callable[[str, str], Optional[str]]] = None,
    sign_and_send_post: Optional[Callable[[str, Dict], Any]] = None,
) -> PollingResult:
    """Poll a pending URL until a terminal response.

    Implements the agent state machine from spec Section 10.6.

    Args:
        pending_url: The Location URL from the 202 response
        sign_and_send_get: Function that sends a signed GET to a URL and returns
            an object with .status_code and .json() method
        max_polls: Maximum number of poll attempts
        default_wait: Default seconds between polls
        on_interaction: Callback when require=interaction is received.
            Called with (interaction_endpoint, code). Agent should direct user there.
        on_clarification: Callback when clarification question is received.
            Called with (pending_url, question). Should return response string or None.
        sign_and_send_post: Function for POST requests (needed for clarification responses).
            Called with (url, json_body).

    Returns:
        PollingResult with the outcome
    """
    for attempt in range(max_polls):
        logger.debug(f"Poll attempt {attempt + 1}/{max_polls}: GET {pending_url}")

        try:
            response = sign_and_send_get(pending_url)
        except Exception as e:
            logger.error(f"Poll request failed: {e}")
            return PollingResult(
                success=False,
                error="network_error",
                error_description=str(e),
            )

        status = response.status_code

        # Terminal: 200 OK — success
        if status == 200:
            body = response.json()
            return PollingResult(
                success=True,
                auth_token=body.get("auth_token"),
                response_body=body,
                status_code=200,
            )

        # Terminal: 403 Denied/Abandoned
        if status == 403:
            body = response.json()
            return PollingResult(
                success=False,
                status_code=403,
                response_body=body,
                error=body.get("error", "denied"),
                error_description=body.get("error_description"),
            )

        # Terminal: 408 Expired
        if status == 408:
            body = response.json()
            return PollingResult(
                success=False,
                status_code=408,
                response_body=body,
                error=body.get("error", "expired"),
                error_description=body.get("error_description"),
            )

        # Terminal: 410 Gone
        if status == 410:
            body = response.json()
            return PollingResult(
                success=False,
                status_code=410,
                response_body=body,
                error=body.get("error", "invalid_code"),
                error_description=body.get("error_description"),
            )

        # Terminal: 500 Server Error
        if status == 500:
            body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            return PollingResult(
                success=False,
                status_code=500,
                response_body=body,
                error=body.get("error", "server_error"),
                error_description=body.get("error_description"),
            )

        # Transient: 429 Too Many Requests (slow_down)
        if status == 429:
            default_wait += 5  # Per spec: increase interval by 5 seconds
            retry_after = default_wait
            retry_header = getattr(response, 'headers', {}).get('retry-after') or getattr(response, 'headers', {}).get('Retry-After')
            if retry_header:
                try:
                    retry_after = max(int(retry_header), default_wait)
                except (ValueError, TypeError):
                    pass
            logger.debug(f"Received 429 slow_down, increasing poll interval to {retry_after}s")
            time.sleep(retry_after)
            continue

        # Transient: 202 Pending or Interacting — continue polling
        if status == 202:
            body = response.json()
            require = body.get("requirement") or body.get("require")
            code = body.get("code")
            # Spec §Clarification Chat: AAuth-Requirement: requirement=clarification MUST
            # be present in the header; the question text is in the body "clarification" field.
            # Check both: header for the requirement signal, body for the question text.
            aauth_req_header = (
                getattr(response, "headers", {}).get("aauth-requirement")
                or getattr(response, "headers", {}).get("AAuth-Requirement")
                or ""
            )
            if not require and "requirement=clarification" in aauth_req_header:
                require = "clarification"
            clarification = body.get("clarification")
            poll_status = body.get("status", "pending")

            # Handle interaction requirement (first time only)
            if require == "interaction" and code and on_interaction and attempt == 0:
                on_interaction(pending_url, code)

            # When status=interacting, user has arrived — stop prompting
            if poll_status == "interacting":
                logger.debug("User has arrived at interaction endpoint (status=interacting)")

            # Handle clarification question
            if clarification and on_clarification and sign_and_send_post:
                answer = on_clarification(pending_url, clarification)
                if answer:
                    try:
                        sign_and_send_post(pending_url, {
                            "clarification_response": answer
                        })
                    except Exception as e:
                        logger.warning(f"Failed to send clarification response: {e}")

            # Respect Retry-After
            retry_after = default_wait
            retry_header = getattr(response, 'headers', {}).get('retry-after') or getattr(response, 'headers', {}).get('Retry-After')
            if retry_header:
                try:
                    retry_after = max(int(retry_header), 0)
                except (ValueError, TypeError):
                    pass

            if retry_after > 0:
                time.sleep(retry_after)
            continue

        # Transient: 503 Temporarily unavailable
        if status == 503:
            retry_after = default_wait * 2
            retry_header = getattr(response, 'headers', {}).get('retry-after') or getattr(response, 'headers', {}).get('Retry-After')
            if retry_header:
                try:
                    retry_after = max(int(retry_header), 1)
                except (ValueError, TypeError):
                    pass
            time.sleep(retry_after)
            continue

        # Unknown status — treat as fatal
        logger.warning(f"Unexpected status code {status} during polling")
        body = {}
        try:
            body = response.json()
        except Exception:
            pass
        return PollingResult(
            success=False,
            status_code=status,
            response_body=body,
            error="unexpected_status",
            error_description=f"Unexpected HTTP status {status}",
        )

    # Exhausted polls
    return PollingResult(
        success=False,
        error="max_polls_exceeded",
        error_description=f"Exceeded maximum {max_polls} poll attempts",
    )


def cancel_pending_request(
    sign_and_send_delete: Callable[[str], Any],
    pending_url: str,
) -> Any:
    """Send DELETE to a pending URL to cancel the request (spec Section 11.4.3).

    The caller must provide ``sign_and_send_delete`` that performs a signed DELETE.
    """
    return sign_and_send_delete(pending_url)
