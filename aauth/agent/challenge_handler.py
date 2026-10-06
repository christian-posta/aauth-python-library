"""Select credentials for published AAuth requirements."""

from ..headers.aauth_header import parse_aauth_header
from ..errors import ChallengeError


class ChallengeHandler:
    def parse_challenge(self, value):
        return parse_aauth_header(value)

    def determine_response_scheme(
        self,
        challenge,
        has_agent_token=False,
        has_auth_token=False,
        has_person_token=False,
    ):
        requirement = challenge.get("requirement") or challenge.get("require")
        available = {
            "agent-token": has_agent_token,
            "person-token": has_person_token,
            "auth-token": has_auth_token,
        }
        if requirement not in available:
            raise ChallengeError(
                "Unsupported or non-credential requirement", challenge_type=requirement
            )
        if not available[requirement]:
            raise ChallengeError(
                "Required token is unavailable", challenge_type=requirement
            )
        return "jwt"
