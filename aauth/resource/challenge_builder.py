"""Draft -11 credential requirements for resources."""

from ..headers.aauth_header import (
    HEADER_AAUTH_REQUIREMENT,
    build_agent_token_requirement,
    build_person_token_requirement,
    build_auth_token_requirement,
)
from .token_issuer import ResourceTokenIssuer


class ChallengeBuilder:
    def __init__(
        self,
        resource_id,
        resource_private_key,
        resource_kid,
        auth_server,
        jwks_fetcher=None,
    ):
        self.args = (
            resource_id,
            resource_private_key,
            resource_kid,
            auth_server,
            jwks_fetcher,
        )

    def build_challenge(
        self,
        require_signature=True,
        require_identity=False,
        require_auth_token=False,
        *,
        require_person_token=False,
        presented_token=None,
        agent_public_key=None,
        scope=None,
        **options,
    ):
        if require_auth_token:
            if not presented_token:
                return HEADER_AAUTH_REQUIREMENT, build_person_token_requirement()
            issuer = ResourceTokenIssuer(*self.args)
            token = issuer.issue_token(
                presented_token, agent_public_key, scope, **options
            )
            return HEADER_AAUTH_REQUIREMENT, build_auth_token_requirement(token)
        if require_person_token:
            return HEADER_AAUTH_REQUIREMENT, build_person_token_requirement()
        return HEADER_AAUTH_REQUIREMENT, build_agent_token_requirement()
