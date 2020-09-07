import datetime
import logging
import uuid
from typing import Any, Mapping, Optional, Tuple, Union

import peewee

from .auth import _create_access_token, _create_refresh_token
from .secret import _create_secret
from ..library import crypto, db, validation
from ..library.config import Range, config
from ..library.error import ConflictError, ForbiddenError, NotFoundError
from ..models.secret import Secret
from ..models.user import User
from ..models.auth import AccessToken, RefreshToken

DB = db.db()


class PublicUserResponse:
    def __init__(self, user: User):
        self.user = user

    def into_dict(self):
        return {
            "user": self.user.into_dict(),
        }


class PrivateUserResponse:
    def __init__(self, user: User):
        self.user = user

    def _secrets(self):
        for secret in self.user.secrets:
            if secret.is_valid():
                yield secret

    def _access_tokens(self):
        for secret in self._secrets():
            for access_token in secret.access_tokens:
                if access_token.is_valid():
                    yield access_token

    def _refresh_tokens(self):
        for access_token in self._access_tokens():
            for refresh_token in access_token.refresh_tokens:
                if refresh_token.is_valid():
                    yield refresh_token

    def into_dict(self):
        return {
            "user":
                self.user.into_dict(),
            "secrets": [secret.into_dict() for secret in self._secrets()],
            "access_tokens": [
                token.into_dict() for token in self._access_tokens()
            ],
            "refresh_tokens": [
                token.into_dict() for token in self._refresh_tokens()
            ],
        }


@DB.atomic()
def create_user(
    create_ts: datetime.datetime,
    name: str,
    secret_plain: str,
    access_token_lifetime: datetime.timedelta,
    refresh_token_lifetime: datetime.timedelta,
) -> CreateUserResponse:
    logging.debug("controllers.user.create_user")

    secret_hash = crypto.hash_secret(secret_plain)

    user = _create_user(create_ts, name)
    secret = _create_secret(name, secret_hash, create_ts, None, user)
    access_token = _create_access_token(
        create_ts,
        create_ts + access_token_lifetime,
        secret,
    )
    refresh_token = _create_refresh_token(
        create_ts,
        create_ts + refresh_token_lifetime,
        access_token,
    )

    return PrivateUserResponse(user)


@DB.atomic()
def read_user(
    server_ts: datetime.datetime,
    name: str,
    access_token_value: Optional[str],
) -> Union[PrivateUserResponse, PublicUserResponse]:
    logging.debug("controllers.user.read_user")

    user, _, authorized = _authorize(server_ts, name, access_token_value)

    if not user:
        raise NotFoundError(f"user {name} does not exist")
    elif authorized:
        return PrivateUserResponse(user)
    else:
        return PublicUserResponse(user)


@DB.atomic()
def update_user(
    server_ts: datetime.datetime, name: str, access_token_value: str,
    **fields: Mapping[str, Any]
) -> PrivateUserResponse:
    logging.debug("controllers.user.update_user")

    user, _, authorized = _authorize(server_ts, name, access_token_value)

    if not user:
        raise NotFoundError(f"user {name} does not exist")
    elif not authorized:
        raise ForbiddenError("cannot update user")

    if "expire_ts" in fields:
        expire_ts = fields["expire_ts"]
        if expire_ts is not None:
            validation.validate_expire_time(
                "expire_ts",
                expire_ts,
                Range(user.create_ts, None),
            )
        user.expire_ts = expire_ts

    if fields:
        user.save()

    return PrivateUserResponse(user)


@DB.atomic()
def delete_user(
    server_ts: datetime.datetime,
    name: str,
    access_token_value: str,
) -> PublicUserResponse:
    logging.debug("controllers.user.update_user")

    user, _, authorized = _authorize(server_ts, name, access_token_value)

    if not user:
        raise NotFoundError(f"user {name} does not exist")
    elif not authorized:
        raise ForbiddenError("cannot delete user")

    user.expire_ts = server_ts
    user.save()

    return PublicUserResponse(user)


def _create_user(server_ts: datetime.datetime, name: str) -> User:
    logging.debug("controllers.user._create_user")

    try:
        return User.create(id=uuid.uuid4(), name=name, create_ts=server_ts)
    except peewee.IntegrityError:
        raise ConflictError(user={"name": "user names must be unique"})


def _authorize(
    server_ts: datetime.datetime,
    name: str,
    access_token_value: str,
) -> Tuple[Optional[User], Optional[AccessToken], bool]:
    user = User.select_by_name(server_ts, name)

    if access_token_value is None:
        access_token = None
    else:
        access_token = AccessToken.select_valid_by_value(
            server_ts,
            access_token_value,
        )

    authorized = user and access_token and (
        user.id == access_token.secret.user.id
    )

    return (user, access_token, authorized)
