from typing import Optional

from .auth import AccessTokenResponse
from ..models.secret import Secret


class SecretResponse:
    def __init__(self, secret: Secret, value: Optional[str] = None):
        self.secret = secret
        self.value = value

    def into_dict(self):
        access_tokens = [
            AccessTokenResponse(access_token).into_dict()
            for access_token in self.secret.access_tokens
        ]

        as_dict = {
            "name": self.secret.name,
            "create_ts": self.secret.create_ts,
            "expire_ts": self.secret.expire_ts,
            "user_name": self.secret.user.name,
            "access_tokens": access_tokens,
        }

        if self.value is not None:
            as_dict["value"] = self.value

        return as_dict
