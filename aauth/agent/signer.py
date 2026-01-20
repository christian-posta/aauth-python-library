"""High-level request signing for agent role."""

from typing import Dict, Any, Optional
from urllib.parse import urlparse
from ..signing.signer import sign_request
from ..headers.signature_key import build_signature_key_header
from ..errors import SignatureError


class AgentRequestSigner:
    """High-level request signer for agents."""
    
    def __init__(
        self,
        private_key,
        agent_id: Optional[str] = None,
        agent_token: Optional[str] = None,
        kid: str = "key-1"
    ):
        """Initialize agent request signer.
        
        Args:
            private_key: Agent's private signing key
            agent_id: Agent identifier (HTTPS URL) - required for jwks scheme
            agent_token: Agent token (JWT) - required for jwt scheme
            kid: Key ID for jwks scheme
        """
        self.private_key = private_key
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.kid = kid
    
    def sign_request(
        self,
        method: str,
        target_uri: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
        sig_scheme: str = "hwk"
    ) -> Dict[str, str]:
        """Sign an HTTP request.
        
        Args:
            method: HTTP method
            target_uri: Target URI
            headers: Request headers (will be modified)
            body: Request body bytes
            sig_scheme: Signature scheme ("hwk", "jwks", or "jwt")
        
        Returns:
            Dictionary with signature headers
        
        Raises:
            SignatureError: If signing fails
        """
        kwargs = {}
        
        if sig_scheme == "jwks":
            if not self.agent_id:
                raise SignatureError("agent_id required for jwks scheme")
            kwargs["id"] = self.agent_id
            kwargs["kid"] = self.kid
        
        elif sig_scheme == "jwt":
            if not self.agent_token:
                raise SignatureError("agent_token required for jwt scheme")
            kwargs["jwt"] = self.agent_token
        
        return sign_request(
            method=method,
            target_uri=target_uri,
            headers=headers,
            body=body,
            private_key=self.private_key,
            sig_scheme=sig_scheme,
            **kwargs
        )

