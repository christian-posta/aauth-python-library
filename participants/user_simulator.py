"""User simulator for automated interaction endpoint flows.

Updated for SPEC_UPDATED.md:
- Uses interaction endpoint with code parameter (not request_token)
- No more redirect_uri / authorization code exchange
- User grants consent at interaction endpoint, agent polls pending URL
"""

import httpx
from typing import Optional
import sys
import os
from urllib.parse import urlparse, parse_qs

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth.debug import _is_debug_enabled


class UserSimulator:
    """Simulates a user browser for automated testing of interaction flows."""

    def __init__(self, username: str = "testuser", password: str = "testpass"):
        self.username = username
        self.password = password
        self.debug = _is_debug_enabled()

    def _extract_hidden_input(self, html: str, name: str) -> str:
        """Extract hidden input value from form HTML."""
        import re
        # Support either quote style and either attribute order.
        patterns = [
            rf'name=[\'"]{name}[\'"][^>]*value=[\'"]([^\'"]+)[\'"]',
            rf'value=[\'"]([^\'"]+)[\'"][^>]*name=[\'"]{name}[\'"]',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, flags=re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    async def complete_interaction(
        self,
        interaction_url: str,
        auth_server_base: Optional[str] = None,
    ) -> bool:
        """Complete the interaction flow: login + grant consent.

        Args:
            interaction_url: Full URL e.g. https://auth.example/interact?code=ABCD1234
            auth_server_base: Base URL of auth server (extracted from URL if not provided)

        Returns:
            True if consent was granted successfully
        """
        if self.debug:
            print(f"DEBUG USER_SIM: Starting interaction flow", file=sys.stderr, flush=True)
            print(f"DEBUG USER_SIM:   URL: {interaction_url}", file=sys.stderr, flush=True)

        parsed_url = urlparse(interaction_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params.get("code", [None])[0]

        if not code:
            if self.debug:
                print(f"DEBUG USER_SIM:   No code found in URL", file=sys.stderr, flush=True)
            return False

        if not auth_server_base:
            auth_server_base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        async with httpx.AsyncClient(follow_redirects=False) as client:
            # Step 1: GET interaction endpoint with code
            response = await client.get(interaction_url, follow_redirects=True)
            # If interaction chaining redirects to another host, post back to final page origin/path.
            interact_endpoint = str(response.url).split("?", 1)[0]
            final_query = parse_qs(response.url.query)
            final_code = final_query.get("code", [None])[0]
            if final_code:
                code = final_code

            if self.debug:
                print(f"DEBUG USER_SIM:   Interaction page: {response.status_code}", file=sys.stderr, flush=True)

            if response.status_code != 200:
                return False

            content = response.text

            # Step 2: Authenticate if login page shown
            if "username" in content.lower() and "password" in content.lower():
                if self.debug:
                    print(f"DEBUG USER_SIM:   Login page detected, authenticating...", file=sys.stderr, flush=True)

                pending_id = self._extract_hidden_input(content, "pending_id")
                form_code = self._extract_hidden_input(content, "code")
                if form_code:
                    code = form_code

                login_response = await client.post(
                    interact_endpoint,
                    data={
                        "pending_id": pending_id,
                        "code": code,
                        "username": self.username,
                        "password": self.password,
                        "action": "login",
                    },
                    follow_redirects=False,
                )

                if self.debug:
                    print(f"DEBUG USER_SIM:   Login response: {login_response.status_code}", file=sys.stderr, flush=True)

                # Follow redirect to consent page
                if login_response.status_code in (302, 303, 307, 308):
                    location = login_response.headers.get("Location")
                    if location:
                        if self.debug:
                            print(f"DEBUG USER_SIM:   Following redirect: {location}", file=sys.stderr, flush=True)
                        response = await client.get(location, follow_redirects=False)
                        content = response.text

            # Step 3: Grant consent
            if "consent" in content.lower() or "grant" in content.lower():
                if self.debug:
                    print(f"DEBUG USER_SIM:   Consent page detected, granting consent...", file=sys.stderr, flush=True)

                pending_id = self._extract_hidden_input(content, "pending_id")
                form_code = self._extract_hidden_input(content, "code")
                if form_code:
                    code = form_code

                consent_response = await client.post(
                    interact_endpoint,
                    data={
                        "pending_id": pending_id,
                        "code": code,
                        "consent": "grant",
                    },
                    follow_redirects=False,
                )

                if self.debug:
                    print(f"DEBUG USER_SIM:   Consent response: {consent_response.status_code}", file=sys.stderr, flush=True)

                # Success: 200 (completion page) or 303 (redirect to callback)
                if consent_response.status_code in (200, 302, 303):
                    if self.debug:
                        print(f"DEBUG USER_SIM:   Consent granted successfully", file=sys.stderr, flush=True)
                    return True

        if self.debug:
            print(f"DEBUG USER_SIM:   Interaction flow completed without granting consent", file=sys.stderr, flush=True)
        return False

    async def deny_interaction(
        self,
        interaction_url: str,
        auth_server_base: Optional[str] = None,
    ) -> bool:
        """Simulate user denying consent at interaction endpoint."""
        if self.debug:
            print(f"DEBUG USER_SIM: Simulating consent denial", file=sys.stderr, flush=True)

        parsed_url = urlparse(interaction_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params.get("code", [None])[0]

        if not code:
            return False

        if not auth_server_base:
            auth_server_base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await client.get(interaction_url, follow_redirects=True)
            interact_endpoint = str(response.url).split("?", 1)[0]
            final_query = parse_qs(response.url.query)
            final_code = final_query.get("code", [None])[0]
            if final_code:
                code = final_code
            if response.status_code != 200:
                return False

            content = response.text

            # Authenticate if needed
            if "username" in content.lower() and "password" in content.lower():
                pending_id = self._extract_hidden_input(content, "pending_id")
                form_code = self._extract_hidden_input(content, "code")
                if form_code:
                    code = form_code

                login_resp = await client.post(
                    interact_endpoint,
                    data={
                        "pending_id": pending_id,
                        "code": code,
                        "username": self.username,
                        "password": self.password,
                        "action": "login",
                    },
                    follow_redirects=False,
                )
                if login_resp.status_code in (302, 303):
                    location = login_resp.headers.get("Location")
                    if location:
                        response = await client.get(location, follow_redirects=False)
                        content = response.text

            # Deny consent
            if "consent" in content.lower():
                pending_id = self._extract_hidden_input(content, "pending_id")
                form_code = self._extract_hidden_input(content, "code")
                if form_code:
                    code = form_code

                consent_resp = await client.post(
                    interact_endpoint,
                    data={
                        "pending_id": pending_id,
                        "code": code,
                        "consent": "deny",
                    },
                    follow_redirects=False,
                )
                return consent_resp.status_code in (200, 302, 303)

        return False
