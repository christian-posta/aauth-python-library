"""Tests for PS token exchange (three-party mode, SPEC §4.1.3)."""

import pytest
import asyncio
import json
import time
from typing import Dict, Any
from urllib.parse import urlparse

from aauth.agent.token_exchange import extract_resource_token, exchange_resource_token
from aauth.tokens.resource_token import create_resource_token
from aauth.tokens.agent_token import create_agent_token
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, calculate_jwk_thumbprint
from aauth.errors import TokenError, MetadataError
import httpx


class TestExtractResourceToken:
    """Tests for extract_resource_token helper."""

    def test_extract_from_valid_challenge_header(self):
        """Extract resource_token from a valid AAuth challenge header."""
        test_token = "eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUifQ.sig"
        headers = {
            "AAuth-Requirement": f'requirement=auth-token; resource-token="{test_token}"'
        }
        result = extract_resource_token(headers)
        assert result == test_token

    def test_extract_from_case_insensitive_header(self):
        """extract_resource_token is case-insensitive for header names."""
        test_token = "eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUifQ.sig"
        headers = {
            "aauth-requirement": f'requirement=auth-token; resource-token="{test_token}"'
        }
        result = extract_resource_token(headers)
        assert result == test_token

    def test_extract_from_missing_header(self):
        """extract_resource_token returns None when no AAuth header present."""
        headers = {"Content-Type": "application/json"}
        result = extract_resource_token(headers)
        assert result is None

    def test_extract_from_header_without_resource_token_param(self):
        """extract_resource_token returns None when resource-token param missing."""
        headers = {"AAuth-Requirement": "requirement=identity"}
        result = extract_resource_token(headers)
        assert result is None

    def test_extract_handles_malformed_header_gracefully(self):
        """extract_resource_token returns None on parse errors."""
        headers = {"AAuth-Requirement": "garbage_header_content"}
        result = extract_resource_token(headers)
        assert result is None
