"""Agent-Auth challenge handling for agent role."""

from typing import Dict, Any, Optional
from ..headers.agent_auth import parse_agent_auth_header
from ..errors import ChallengeError


class ChallengeHandler:
    """Handles Agent-Auth challenges from resources."""
    
    def parse_challenge(self, agent_auth_header: str) -> Dict[str, Any]:
        """Parse Agent-Auth challenge header.
        
        Args:
            agent_auth_header: Agent-Auth header value
            
        Returns:
            Parsed challenge parameters
            
        Raises:
            ChallengeError: If parsing fails
        """
        return parse_agent_auth_header(agent_auth_header)
    
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
            Signature scheme to use ("hwk", "jwks", or "jwt")
            
        Raises:
            ChallengeError: If challenge cannot be satisfied
        """
        if challenge.get("auth_token"):
            if has_auth_token:
                return "jwt"
            else:
                raise ChallengeError(
                    "Challenge requires auth token but agent doesn't have one",
                    challenge_type="auth-token"
                )
        
        if challenge.get("identity"):
            if has_agent_token:
                return "jwt"  # Use agent token
            else:
                return "jwks"  # Use agent server identity
        
        # Just signature required
        return "hwk"

