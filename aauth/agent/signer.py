"""Agent signing under the AAuth jwt profile."""

from ..signing.signer import sign_request
from ..errors import SignatureError


class AgentRequestSigner:
    def __init__(self, private_key, agent_id=None, agent_token=None, **kwargs):
        self.private_key = private_key
        self.agent_id = agent_id
        self.agent_token = agent_token

    def sign_request(
        self,
        method,
        target_uri,
        headers,
        body=None,
        sig_scheme="jwt",
        *,
        token=None,
        recipient_role="resource",
        additional_signature_components=None,
    ):
        if sig_scheme != "jwt":
            raise SignatureError(
                "AAuth agents must use jwt", error_code="unsupported_scheme"
            )
        token = token or self.agent_token
        if not token:
            raise SignatureError("A token is required")
        components = list(additional_signature_components or [])
        if body is not None and recipient_role in ("ps", "as", "revocation"):
            components.extend(["content-digest", "content-type"])
        return sign_request(
            method,
            target_uri,
            headers,
            body,
            self.private_key,
            sig_scheme="jwt",
            jwt=token,
            additional_signature_components=components,
        )
