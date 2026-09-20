from ..models.auth import AccessToken, RefreshToken


class AccessTokenResponse:
    def __init__(self, access_token: AccessToken):
        self.access_token = access_token

    def into_dict(self):
        refresh_tokens = [
            RefreshTokenResponse(refresh_token).into_dict()
            for refresh_token in self.access_token.refresh_tokens
        ]

        return {
            "value": self.access_token.value,
            "create_ts": self.access_token.create_ts,
            "expire_ts": self.access_token.expire_ts,
            "secret_name": self.access_token.secret.name,
            "refresh_tokens": refresh_tokens,
        }


class RefreshTokenResponse:
    def __init__(self, refresh_token: RefreshToken):
        self.refresh_token = refresh_token

    def into_dict(self):
        return {
            "value": self.refresh_token.value,
            "create_ts": self.refresh_token.create_ts,
            "expire_ts": self.refresh_token.expire_ts,
            "access_token_value": self.refresh_token.access_token.value,
        }
