from .secret import SecretResponse
from ..models.user import User


class PublicUserResponse:
    def __init__(self, user: User):
        self.user = user

    def into_dict(self):
        return {
            "id": self.user.id,
            "name": self.user.name,
            "create_ts": self.user.create_ts,
            "expire_ts": self.user.expire_ts,
        }


class PrivateUserResponse:
    def __init__(self, user: User):
        self.user = user

    def into_dict(self):
        secrets = [
            SecretResponse(secret).into_dict() for secret in self.user.secrets
        ]

        return {
            "id": self.user.id,
            "name": self.user.name,
            "create_ts": self.user.create_ts,
            "expire_ts": self.user.expire_ts,
            "secrets": secrets,
        }
