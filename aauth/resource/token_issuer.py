"""Resource issuance requires a verified presented person/auth token."""

from ..tokens.resource_token import create_resource_token
from ..keys.jwk import calculate_jwk_thumbprint, public_key_to_jwk


class ResourceTokenIssuer:
    def __init__(
        self,
        resource_id,
        resource_private_key,
        resource_kid,
        auth_server,
        jwks_fetcher,
        revocation_checker=None,
    ):
        self.resource_id = resource_id
        self.resource_private_key = resource_private_key
        self.resource_kid = resource_kid
        self.auth_server = auth_server
        self.jwks_fetcher = jwks_fetcher
        self.revocation_checker = revocation_checker

    def issue_token(
        self, presented_token, agent_public_key, scope=None, exp=None, **options
    ):
        return create_resource_token(
            self.resource_id,
            self.auth_server,
            calculate_jwk_thumbprint(public_key_to_jwk(agent_public_key)),
            self.resource_private_key,
            self.resource_kid,
            presented_token=presented_token,
            jwks_fetcher=self.jwks_fetcher,
            scope=scope,
            exp=exp,
            revocation_checker=self.revocation_checker,
            **options,
        )
