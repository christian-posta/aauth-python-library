"""Agent-Auth challenge building for resource role."""

from typing import Optional, List
from ..headers.agent_auth import build_agent_auth_challenge
from ..tokens.resource_token import create_resource_token
from ..keys.jwk import calculate_jwk_thumbprint, public_key_to_jwk
from ..errors import ChallengeError


class ChallengeBuilder:
    """Builds Agent-Auth challenges for resources."""
    
    def __init__(
        self,
        resource_id: str,
        resource_private_key,
        resource_kid: str,
        auth_server: str
    ):
        """Initialize challenge builder.
        
        Args:
            resource_id: Resource identifier (HTTPS URL)
            resource_private_key: Resource's private key for signing resource tokens
            resource_kid: Resource's key ID
            auth_server: Auth server identifier (HTTPS URL)
        """
        self.resource_id = resource_id
        self.resource_private_key = resource_private_key
        self.resource_kid = resource_kid
        self.auth_server = auth_server
    
    def build_challenge(
        self,
        require_signature: bool = True,
        require_identity: bool = False,
        require_auth_token: bool = False,
        agent_id: Optional[str] = None,
        agent_public_key=None,
        scope: Optional[str] = None
    ) -> str:
        """Build Agent-Auth challenge header.
        
        Args:
            require_signature: Require HTTP signature
            require_identity: Require agent identity
            require_auth_token: Require authorization token
            agent_id: Agent identifier (for resource token)
            agent_public_key: Agent's public key (for resource token)
            scope: Required scope (for resource token)
        
        Returns:
            Agent-Auth header value
        
        Raises:
            ChallengeError: If challenge cannot be built
        """
        resource_token = None
        
        if require_auth_token:
            if not agent_id or not agent_public_key or not scope:
                raise ChallengeError(
                    "agent_id, agent_public_key, and scope required for auth-token challenge"
                )
            
            # Create resource token
            agent_jwk = public_key_to_jwk(agent_public_key)
            agent_jkt = calculate_jwk_thumbprint(agent_jwk)
            
            resource_token = create_resource_token(
                iss=self.resource_id,
                aud=self.auth_server,
                agent=agent_id,
                agent_jkt=agent_jkt,
                scope=scope,
                private_key=self.resource_private_key,
                kid=self.resource_kid
            )
        
        return build_agent_auth_challenge(
            require_signature=require_signature,
            require_identity=require_identity,
            require_auth_token=require_auth_token,
            resource_token=resource_token,
            auth_server=self.auth_server if require_auth_token else None
        )

