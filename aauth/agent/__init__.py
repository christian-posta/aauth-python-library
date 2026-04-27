"""Agent role implementation for AAuth."""

from .signer import AgentRequestSigner
from .challenge_handler import ChallengeHandler
from .token_exchange import exchange_resource_token, extract_resource_token

__all__ = [
    "AgentRequestSigner",
    "ChallengeHandler",
    "exchange_resource_token",
    "extract_resource_token",
]

