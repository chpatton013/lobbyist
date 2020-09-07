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

DB = db.db()


class AccessTokenResponse:
    def __init__(self, access_token: AccessToken):
        self.access_token = access_token

    def _refresh_tokens(self):
        for refresh_token in self.access_token.refresh_tokens:
            if refresh_token.is_valid():
                yield refresh_token

    def into_dict(self):
        as_dict = self.access_token.into_dict()
        as_dict["refresh_tokens"] = self._refresh_tokens()
        return as_dict


@DB.atomic()
def create_access_token(
    create_ts: datetime.datetime,
    name: str,
    value: str,
    access_token_lifetime: datetime.timedelta,
    refresh_token_lifetime: datetime.timedelta,
) -> AccessTokenResponse:
    logging.debug("controllers.auth.create_access_token")

    secret = _authenticate_secret(create_ts, name, value)

    if not secret:
        raise UnauthorizedError(
            "secret is invalid or does not match a valid hash"
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

    return AccessTokenResponse(access_token)


@DB.atomic()
def read_access_token(
    server_ts: datetime.datetime,
    value: str,
    access_token_value: str,
) -> AccessTokenResponse:
    logging.debug("controllers.auth.read_access_token")

    access_token, _, authorized = _authorize(
        server_ts,
        value,
        access_token_value,
    )

    if not authorized:
        raise ForbiddenError("cannot read access token")

    return AccessTokenResponse(access_token)


@DB.atomic()
def refresh_token(
    server_ts: datetime.datetime,
    token: str,
    access_token_lifetime: datetime.timedelta,
    refresh_token_lifetime: datetime.timedelta,
) -> CreateTokenResponse:
    logging.debug("controllers.auth.refresh_token")
    pass


def _authenticate_secret(
    server_ts: datetime.datetime,
    name: str,
    value: str,
) -> Optional[Secret]:
    secret = Secret.select_valid_by_name(server_ts, name).get()

    # We combine these two failure modes to obfuscate responses to brute-force
    # attacks. Attackers should not be able to tell the difference between
    # unknown secret keys, expired secrets, and incorrect secret values.
    if not secret or not bcrypt.checkpw(value.encode(), secret.hash.encode()):
        return None

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


def _authorize(
    server_ts: datetime.datetime,
    value: str,
    access_token_value: str,
) -> Tuple[Optional[AccessToken], Optional[AccessToken], bool]:
    requested_access_token = AccessToken.select_by_value(server_ts, value)

    if access_token_value is None:
        requesting_access_token = None
    else:
        requesting_access_token = AccessToken.select_valid_by_value(
            server_ts,
            access_token_value,
        )

    authorized = requested_access_token and requesting_access_token and (
        requested_access_token.id == requesting_access_token.secret.user.id
    )

    return (requested_access_token, requesting_access_token, authorized)
