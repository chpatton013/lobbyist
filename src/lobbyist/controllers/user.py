import datetime
import logging
import uuid
from typing import Any, Mapping, Optional, Tuple, Union

import peewee

from .auth import (
    _authorize_access_token,
    _create_access_token,
    _create_refresh_token,
)
from .secret import _create_secret
from ..library import crypto, db, validation
from ..library.config import Range, config
from ..library.error import ConflictError, ForbiddenError, NotFoundError
from ..models.user import User
from ..models.auth import AccessToken
from ..responses.user import PublicUserResponse, PrivateUserResponse

DB = db.db()


@DB.atomic()
def create_user(
    create_ts: datetime.datetime,
    user_name: str,
    secret_plain: str,
    access_token_lifetime: datetime.timedelta,
    refresh_token_lifetime: datetime.timedelta,
) -> PrivateUserResponse:
    logging.debug("controllers.user.create_user")

    secret_hash = crypto.hash_secret(secret_plain)

    user = _create_user(create_ts, user_name)
    secret = _create_secret(
        user_name,
        secret_hash,
        create_ts,
        None,  # expire_ts
        True,  # is_password
        user,
    )
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
    auth_access_token_value: Optional[str],
    user_name: str,
) -> Union[PrivateUserResponse, PublicUserResponse]:
    logging.debug("controllers.user.read_user")

    user, authorized = _try_authorize_user(server_ts, auth_access_token_value, user_name)

    if authorized:
        return PrivateUserResponse(user)
    else:
        return PublicUserResponse(user)


@DB.atomic()
def update_user(
    server_ts: datetime.datetime, auth_access_token_value: str, user_name: str,
    **fields: Mapping[str, Any]
) -> PrivateUserResponse:
    logging.debug("controllers.user.update_user")

    user = _authorize_user(server_ts, auth_access_token_value, user_name)

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
    auth_access_token_value: str,
    user_name: str,
) -> PublicUserResponse:
    logging.debug("controllers.user.update_user")

    user = _authorize_user(server_ts, auth_access_token_value, user_name)
    user.expire_ts = server_ts
    user.save()

    return PublicUserResponse(user)


def _create_user(server_ts: datetime.datetime, user_name: str) -> User:
    logging.debug("controllers.user._create_user")

    try:
        return User.create(id=uuid.uuid4(), name=user_name, create_ts=server_ts)
    except peewee.IntegrityError:
        raise ConflictError(user={"name": "user names must be unique"})


def _read_user(
    server_ts: datetime.datetime,
    user_name: str,
) -> User:
    user = User.select_by_name(server_ts, user_name)
    if not user:
        raise NotFoundError(f"user {user_name} does not exist")
    return user


def _is_authorized_for_user(user: User, access_token: AccessToken) -> bool:
    return (user.id == access_token.secret.user.id)


def _try_authorize_user(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    user_name: str,
) -> Tuple[User, bool]:
    user = _read_user(server_ts, user_name)
    try:
        access_token = _authorize_access_token(server_ts, auth_access_token_value)
    except UnauthorizedError:
        return (user, False)
    return (user, _is_authorized_for_user(user, access_token))


def _authorize_user(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    user_name: str,
) -> User:
    user = _read_user(server_ts, user_name)
    access_token = _authorize_access_token(server_ts, auth_access_token_value)
    if not _is_authorized_for_user(user, access_token):
        raise ForbiddenError("cannot access user")

    return user
