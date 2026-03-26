"""AAuth challenge handling for agent role."""

from typing import Dict, Any, Optional
from ..headers.aauth_header import parse_aauth_header, REQUIRE_AUTH_TOKEN, REQUIRE_IDENTITY, REQUIRE_INTERACTION, REQUIRE_APPROVAL
from ..errors import ChallengeError


class ChallengeHandler:
    """Handles AAuth challenges from resources and auth servers."""

    def parse_challenge(self, aauth_header: str) -> Dict[str, Any]:
        """Parse AAuth challenge header.

        Args:
            aauth_header: AAuth header value

        Returns:
            Parsed challenge parameters

        Raises:
            ChallengeError: If parsing fails
        """
        return parse_aauth_header(aauth_header)

    def determine_response_scheme(
        self,
        challenge: Dict[str, Any],
        has_agent_token: bool = False,
        has_auth_token: bool = False
    ) -> str:
        """Determine which signature scheme to use in response to challenge.

        Args:
            challenge: Parsed challenge parameters
            has_agent_token: Whether agent has an agent token
            has_auth_token: Whether agent has an auth token

        Returns:
            Signature scheme to use ("hwk", "jwks_uri", or "jwt")

        Raises:
            ChallengeError: If challenge cannot be satisfied
        """
        require = challenge.get("require")

        if require == REQUIRE_AUTH_TOKEN:
            if has_auth_token:
                return "jwt"
            else:
                raise ChallengeError(
                    "Challenge requires auth token but agent doesn't have one",
                    challenge_type="auth-token"
                )

        if require == REQUIRE_IDENTITY:
            if has_agent_token:
                return "jwt"
            else:
                return "jwks_uri"

        # Pseudonym or other — just sign with hwk
        return "hwk"
