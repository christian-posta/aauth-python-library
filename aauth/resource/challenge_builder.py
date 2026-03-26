"""AAuth challenge building for resource role."""

from typing import Optional
from ..headers.aauth_header import (
    build_pseudonym_challenge,
    build_identity_challenge,
    build_auth_token_challenge,
)
from ..tokens.resource_token import create_resource_token
from ..keys.jwk import calculate_jwk_thumbprint, public_key_to_jwk
from ..errors import ChallengeError


class ChallengeBuilder:
    """Builds AAuth challenges for resources."""

    def __init__(
        self,
        resource_id: str,
        resource_private_key,
        resource_kid: str,
        auth_server: str
    ):
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
        """Build AAuth challenge header value.

        Args:
            require_signature: Require HTTP signature (pseudonym level)
            require_identity: Require agent identity
            require_auth_token: Require authorization token
            agent_id: Agent identifier (for resource token)
            agent_public_key: Agent's public key (for resource token)
            scope: Required scope (for resource token)

        Returns:
            AAuth header value

        Raises:
            ChallengeError: If challenge cannot be built
        """
        if require_auth_token:
            if not agent_id or not agent_public_key or not scope:
                raise ChallengeError(
                    "agent_id, agent_public_key, and scope required for auth-token challenge"
                )

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

            return build_auth_token_challenge(resource_token, self.auth_server)

        if require_identity:
            return build_identity_challenge()

        return build_pseudonym_challenge()
