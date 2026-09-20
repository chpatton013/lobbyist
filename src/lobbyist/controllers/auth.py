import base64
import bcrypt
import datetime
import logging
import uuid
from typing import Optional, Tuple

import peewee

from ..library import crypto, db
from ..library.config import config
from ..library.error import UnauthorizedError
from ..models.secret import Secret
from ..models.auth import AccessToken, RefreshToken
from ..responses.auth import AccessTokenResponse, RefreshTokenResponse

DB = db.db()


@DB.atomic()
def create_access_token(
    create_ts: datetime.datetime,
    secret_name: str,
    secret_value: str,
    access_token_lifetime: datetime.timedelta,
    refresh_token_lifetime: datetime.timedelta,
) -> AccessTokenResponse:
    logging.debug("controllers.auth.create_access_token")

    secret = _authenticate_secret(create_ts, secret_name, secret_value)
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

    return AccessTokenResponse(access_token)


@DB.atomic()
def read_access_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    access_token_value: str,
) -> AccessTokenResponse:
    logging.debug("controllers.auth.read_access_token")

    access_token = _authorize_requested_access_token(
        server_ts,
        auth_access_token_value,
        access_token_value,
    )
    return AccessTokenResponse(access_token)


@DB.atomic()
def update_access_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    access_token_value: str,
    **fields: Mapping[str, Any]
) -> AccessTokenResponse:
    logging.debug("controllers.auth.update_access_token")

    access_token = _authorize_requested_access_token(
        server_ts,
        auth_access_token_value,
        access_token_value,
    )

    if "expire_ts" in fields:
        expire_ts = fields["expire_ts"]
        if expire_ts is not None:
            validation.validate_expire_time(
                "expire_ts",
                expire_ts,
                Range(access_token.create_ts, access_token.expire_ts),
            )

        access_token.expire_ts = expire_ts

    if fields:
        access_token.save()

    return AccessTokenResponse(access_token)


@DB.atomic()
def delete_access_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    access_token_value: str,
) -> AccessTokenResponse:
    logging.debug("controllers.auth.delete_access_token")

    access_token = _authorize_requested_access_token(
        server_ts,
        auth_access_token_value,
        access_token_value,
    )

    access_token.expire_ts = server_ts
    access_token.save()

    return AccessTokenResponse(access_token)


@DB.atomic()
def refresh_access_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    refresh_token_value: str,
    access_token_lifetime: datetime.timedelta,
    refresh_token_lifetime: datetime.timedelta,
) -> AccessTokenResponse:
    logging.debug("controllers.auth.refresh_access_token")

    _authorize_refresh_token(server_ts, auth_access_token_value, refresh_token_value)

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

    return AccessTokenResponse(access_token)


@DB.atomic()
def read_refresh_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    refresh_token_value: str,
) -> RefreshTokenResponse:
    logging.debug("controllers.auth.read_refresh_token")

    refresh_token = _authorize_refresh_token(
        server_ts,
        auth_access_token_value,
        refresh_token_value,
    )
    return RefreshTokenResponse(refresh_token)


@DB.atomic()
def update_refresh_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    refresh_token_value: str,
    **fields: Mapping[str, Any]
) -> RefreshTokenResponse:
    logging.debug("controllers.auth.update_refresh_token")

    refresh_token = _authorize_refresh_token(
        server_ts,
        auth_access_token_value,
        refresh_token_value,
    )

    if "expire_ts" in fields:
        expire_ts = fields["expire_ts"]
        if expire_ts is not None:
            validation.validate_expire_time(
                "expire_ts",
                expire_ts,
                Range(refresh_token.create_ts, refresh_token.expire_ts),
            )

        refresh_token.expire_ts = expire_ts

    if fields:
        refresh_token.save()

    return RefreshTokenResponse(refresh_token)


@DB.atomic()
def delete_refresh_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    refresh_token_value: str,
) -> RefreshTokenResponse:
    logging.debug("controllers.auth.delete_refresh_token")

    refresh_token = _authorize_refresh_token(
        server_ts,
        auth_access_token_value,
        refresh_token_value,
    )

    refresh_token.expire_ts = server_ts
    refresh_token.save()

    return RefreshTokenResponse(refresh_token)


def _authenticate_secret(
    server_ts: datetime.datetime,
    secret_name: str,
    secret_value: str,
) -> Secret:
    secret = Secret.select_valid_by_name(server_ts, secret_name).get()

    # We combine these two failure modes to obfuscate responses to brute-force
    # attacks. Attackers should not be able to tell the difference between
    # unknown secret keys, expired secrets, and incorrect secret values.
    if not secret or not bcrypt.checkpw(secret_value.encode(), secret.hash.encode()):
        raise UnauthorizedError(
            "secret is invalid or does not match a valid hash"
        )

    return secret


def _create_access_token(
    create_ts: datetime.datetime,
    expire_ts: datetime.datetime,
    secret: Secret,
) -> AccessToken:
    logging.debug("controllers.auth._create_access_token")

    try:
        return AccessToken.create(
            id=uuid.uuid4(),
            value=crypto.make_secret_string(config().access_token_entropy),
            create_ts=create_ts,
            expire_ts=expire_ts,
            secret=secret,
        )
    except peewee.IntegrityError:
        raise ConflictError(user={"name": "access token values must be unique"})


def _create_refresh_token(
    create_ts: datetime.datetime,
    expire_ts: datetime.datetime,
    access_token: AccessToken,
) -> RefreshToken:
    logging.debug("controllers.auth._create_refresh_token")

    try:
        return RefreshToken.create(
            id=uuid.uuid4(),
            value=crypto.make_secret_string(config().refresh_token_entropy),
            create_ts=create_ts,
            expire_ts=expire_ts,
            access_token=access_token,
        )
    except peewee.IntegrityError:
        raise ConflictError(
            user={"name": "refresh token values must be unique"}
        )


def _authorize_access_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
) -> AccessToken:
    access_token = AccessToken.select_valid_by_value(
        server_ts,
        auth_access_token_value,
    )
    if not access_token:
        raise UnauthorizedError("access token is not authorized")

    return access_token


def _authorize_requested_access_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    access_token_value: str,
) -> AccessToken:
    requesting_access_token = _authorize_access_token(
        server_ts,
        auth_access_token_value,
    )

    requested_access_token = AccessToken.select_by_value(server_ts, access_token_value)
    if not requested_access_token:
        raise NotFoundError(f"access token {access_token_value} does not exist")

    if (
        requesting_access_token.secret.user.id !=
        requested_access_token.secret.user.id
    ):
        raise ForbiddenError("cannot access token")

    return requested_access_token


def _authorize_refresh_token(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    refresh_token_value: str,
) -> RefreshToken:
    access_token = _authorize_access_token(
        server_ts,
        auth_access_token_value,
    )

    refresh_token = RefreshToken.select_by_value(server_ts, refresh_token_value)
    if not refresh_token:
        raise NotFoundError(f"refresh token {refresh_token_value} does not exist")

    if access_token.secret.user.id != refresh_token.secret.user.id:
        raise ForbiddenError("cannot access token")

    return refresh_token
