"""Resource token issuance for resource role."""

from typing import Optional
from ..tokens.resource_token import create_resource_token
from ..keys.jwk import calculate_jwk_thumbprint, public_key_to_jwk
from ..errors import TokenError


class ResourceTokenIssuer:
    """Issues resource tokens for agents."""
    
    def __init__(
        self,
        resource_id: str,
        resource_private_key,
        resource_kid: str,
        auth_server: str
    ):
        """Initialize resource token issuer.
        
        Args:
            resource_id: Resource identifier (HTTPS URL)
            resource_private_key: Resource's private key for signing
            resource_kid: Resource's key ID
            auth_server: Auth server identifier (HTTPS URL)
        """
        self.resource_id = resource_id
        self.resource_private_key = resource_private_key
        self.resource_kid = resource_kid
        self.auth_server = auth_server
    
    def issue_token(
        self,
        agent_id: str,
        agent_public_key,
        scope: str,
        exp: Optional[int] = None
    ) -> str:
        """Issue a resource token.
        
        Args:
            agent_id: Agent identifier (HTTPS URL)
            agent_public_key: Agent's public signing key
            scope: Space-separated scope values
            exp: Optional expiration timestamp
        
        Returns:
            Resource token (JWT string)
        
        Raises:
            TokenError: If token creation fails
        """
        try:
            # Calculate agent JWK thumbprint
            agent_jwk = public_key_to_jwk(agent_public_key)
            agent_jkt = calculate_jwk_thumbprint(agent_jwk)
            
            # Create resource token
            return create_resource_token(
                iss=self.resource_id,
                aud=self.auth_server,
                agent=agent_id,
                agent_jkt=agent_jkt,
                scope=scope,
                private_key=self.resource_private_key,
                kid=self.resource_kid,
                exp=exp
            )
        except Exception as e:
            raise TokenError(
                f"Failed to issue resource token: {e}",
                token_type="resource+jwt"
            ) from e

