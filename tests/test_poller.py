"""Unit tests for async_poll_pending_url (aauth/agent/poller.py)."""

import pytest
import asyncio
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

from aauth.agent.poller import async_poll_pending_url, PollingResult


def make_response(status_code: int, body: dict, headers: dict = None):
    """Build a mock response object."""
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = body
    r.headers = headers or {}
    return r


class TestAsyncPollPendingUrl:
    """Tests for async_poll_pending_url."""

    def run(self, coro):
        return asyncio.run(coro)

    # ------------------------------------------------------------------ #
    # Terminal responses                                                   #
    # ------------------------------------------------------------------ #

    def test_200_returns_success(self):
        get = AsyncMock(return_value=make_response(200, {"auth_token": "tok123"}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is True
        assert result.auth_token == "tok123"
        assert result.status_code == 200
        get.assert_awaited_once_with("http://ps/pending/1")

    def test_403_returns_denied(self):
        get = AsyncMock(return_value=make_response(403, {"error": "denied", "error_description": "User rejected"}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is False
        assert result.error == "denied"
        assert result.error_description == "User rejected"
        assert result.status_code == 403

    def test_408_returns_expired(self):
        get = AsyncMock(return_value=make_response(408, {"error": "expired"}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is False
        assert result.error == "expired"

    def test_410_returns_invalid_code(self):
        get = AsyncMock(return_value=make_response(410, {}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is False
        assert result.error == "invalid_code"

    def test_500_returns_server_error(self):
        get = AsyncMock(return_value=make_response(500, {"error": "server_error"}, {"content-type": "application/json"}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is False
        assert result.error == "server_error"

    def test_unknown_status_is_fatal(self):
        get = AsyncMock(return_value=make_response(418, {}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is False
        assert result.error == "unexpected_status"

    # ------------------------------------------------------------------ #
    # Transient — 202 pending then success                                 #
    # ------------------------------------------------------------------ #

    def test_202_then_200(self):
        responses = [
            make_response(202, {"status": "pending"}, {"Retry-After": "0"}),
            make_response(200, {"auth_token": "tok_final"}),
        ]
        get = AsyncMock(side_effect=responses)

        result = self.run(async_poll_pending_url("http://ps/pending/1", get, default_wait=0))

        assert result.success is True
        assert result.auth_token == "tok_final"
        assert get.await_count == 2

    def test_max_polls_exceeded(self):
        get = AsyncMock(return_value=make_response(202, {"status": "pending"}, {"Retry-After": "0"}))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get, max_polls=3, default_wait=0))

        assert result.success is False
        assert result.error == "max_polls_exceeded"
        assert get.await_count == 3

    # ------------------------------------------------------------------ #
    # Interaction callback                                                 #
    # ------------------------------------------------------------------ #

    def test_on_interaction_called_on_first_poll(self):
        interaction_calls = []

        async def on_interaction(pending_url, code):
            interaction_calls.append((pending_url, code))

        responses = [
            make_response(202, {"status": "pending", "requirement": "interaction", "code": "ABCD1234"}, {"Retry-After": "0"}),
            make_response(202, {"status": "interacting"}, {"Retry-After": "0"}),
            make_response(200, {"auth_token": "tok_after_interaction"}),
        ]
        get = AsyncMock(side_effect=responses)

        result = self.run(async_poll_pending_url(
            "http://ps/pending/1", get, default_wait=0, on_interaction=on_interaction,
        ))

        assert result.success is True
        assert len(interaction_calls) == 1
        assert interaction_calls[0] == ("http://ps/pending/1", "ABCD1234")

    def test_on_interaction_not_called_after_first_poll(self):
        """on_interaction fires only on attempt 0, not on subsequent 202s."""
        interaction_calls = []

        async def on_interaction(pending_url, code):
            interaction_calls.append(code)

        # First 202 has no interaction (so callback won't fire on attempt 0 either,
        # but second 202 does — should be ignored since attempt != 0)
        responses = [
            make_response(202, {"status": "pending"}, {"Retry-After": "0"}),
            make_response(202, {"status": "pending", "requirement": "interaction", "code": "LATE99"}, {"Retry-After": "0"}),
            make_response(200, {"auth_token": "tok"}),
        ]
        get = AsyncMock(side_effect=responses)

        self.run(async_poll_pending_url(
            "http://ps/pending/1", get, default_wait=0, on_interaction=on_interaction,
        ))

        assert interaction_calls == []  # no call: first 202 had no code, second wasn't attempt 0

    # ------------------------------------------------------------------ #
    # Clarification callback                                               #
    # ------------------------------------------------------------------ #

    def test_on_clarification_answer_posted(self):
        clarification_calls = []

        async def on_clarification(pending_url, question):
            clarification_calls.append(question)
            return "yes"

        post = AsyncMock(return_value=make_response(202, {"status": "pending"}, {"Retry-After": "0"}))

        responses = [
            make_response(
                202,
                {"status": "pending", "clarification": "Do you approve?"},
                {"Retry-After": "0", "AAuth-Requirement": "requirement=clarification"},
            ),
            make_response(200, {"auth_token": "tok_clarified"}),
        ]
        get = AsyncMock(side_effect=responses)

        result = self.run(async_poll_pending_url(
            "http://ps/pending/1", get, default_wait=0,
            on_clarification=on_clarification, sign_and_send_post=post,
        ))

        assert result.success is True
        assert clarification_calls == ["Do you approve?"]
        post.assert_awaited_once_with("http://ps/pending/1", {"clarification_response": "yes"})

    def test_on_clarification_none_answer_skips_post(self):
        async def on_clarification(pending_url, question):
            return None  # user didn't answer

        post = AsyncMock()
        responses = [
            make_response(202, {"status": "pending", "clarification": "Approve?"}, {"Retry-After": "0", "AAuth-Requirement": "requirement=clarification"}),
            make_response(200, {"auth_token": "tok"}),
        ]
        get = AsyncMock(side_effect=responses)

        self.run(async_poll_pending_url(
            "http://ps/pending/1", get, default_wait=0,
            on_clarification=on_clarification, sign_and_send_post=post,
        ))

        post.assert_not_awaited()

    # ------------------------------------------------------------------ #
    # 429 slow_down                                                        #
    # ------------------------------------------------------------------ #

    def test_429_increases_wait_and_retries(self):
        responses = [
            make_response(429, {}, {"Retry-After": "0"}),
            make_response(200, {"auth_token": "tok_after_429"}),
        ]
        get = AsyncMock(side_effect=responses)

        result = self.run(async_poll_pending_url("http://ps/pending/1", get, default_wait=0))

        assert result.success is True
        assert get.await_count == 2

    # ------------------------------------------------------------------ #
    # Network error                                                        #
    # ------------------------------------------------------------------ #

    def test_network_error_returns_failure(self):
        get = AsyncMock(side_effect=ConnectionError("timeout"))

        result = self.run(async_poll_pending_url("http://ps/pending/1", get))

        assert result.success is False
        assert result.error == "network_error"
        assert "timeout" in result.error_description
