import datetime
import logging
import uuid
from typing import Any, Mapping, Optional, Tuple

import peewee

from .auth import _authorize_access_token
from ..library import crypto, db, validation
from ..library.config import Range, config
from ..library.error import BadRequestError, ConflictError, ForbiddenError
from ..models.auth import AccessToken
from ..models.secret import Secret
from ..models.user import User
from ..responses.secret import SecretResponse

DB = db.db()


@DB.atomic()
def create_secret(
    create_ts: datetime.datetime,
    auth_access_token_value: str,
    expire_ts: Optional[datetime.datetime],
) -> SecretResponse:
    logging.debug("controllers.secret.create_secret")

    access_token = _authorize_access_token(create_ts, auth_access_token_value)
    secret_name = crypto.make_secret_string(config().secret_name_entropy)
    secret_plain = crypto.make_secret_string(config().secret_value_entropy)
    secret_hash = crypto.hash_secret(secret_plain)

    secret = _create_secret(
        secret_name,
        secret_hash,
        create_ts,
        expire_ts,
        False,  # is_password
        access_token.secret.user,
    )

    return SecretResponse(secret, secret_plain)


@DB.atomic()
def read_secret(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    secret_name: str,
) -> SecretResponse:
    logging.debug("controllers.secret.read_secret")

    secret = _authorize_secret(server_ts, auth_access_token_value, secret_name)
    return SecretResponse(secret)


@DB.atomic()
def update_secret(
    server_ts: datetime.datetime, auth_access_token_value: str, secret_name: str,
    **fields: Mapping[str, Any]
) -> SecretResponse:
    logging.debug("controllers.secret.update_secret")

    secret = _authorize_secret(server_ts, auth_access_token_value, secret_name)

    if "value" in fields:
        if secret_name != secret.user.name:
            raise BadRequestError(
                "cannot change secret",
                fields={"value": "secret value must not be set"},
            )

            value = fields["value"]
            validation.validate_secret("value", value)

            secret.hash = crypto.hash_secret(secret_plain)

    if "expire_ts" in fields:
        if secret_name == secret.user.name:
            raise BadRequestError(
                "cannot expire password",
                fields={"expire_ts": "expire time must not be set"},
            )

        expire_ts = fields["expire_ts"]
        if expire_ts is not None:
            validation.validate_expire_time(
                "expire_ts",
                expire_ts,
                Range(secret.create_ts, secret.expire_ts),
            )

        secret.expire_ts = expire_ts

    if fields:
        secret.save()

    return SecretResponse(secret)


@DB.atomic()
def delete_secret(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    secret_name: str,
) -> SecretResponse:
    logging.debug("controllers.secret.update_secret")

    secret = _authorize_secret(server_ts, auth_access_token_value, secret_name)
    if secret.is_password:
        raise BadRequestError(
            "cannot delete secret",
            records={"is_password": "passwords cannot be deleted"},
        )

    secret.expire_ts = server_ts
    secret.save()

    return SecretResponse(secret)


def _create_secret(
    secret_name: str,
    hash: str,
    create_ts: datetime.datetime,
    expire_ts: Optional[datetime.datetime],
    is_password: bool,
    user: User,
) -> Secret:
    logging.debug("controllers.secret._create_secret")

    try:
        return Secret.create(
            id=uuid.uuid4(),
            name=secret_name,
            hash=hash,
            create_ts=create_ts,
            expire_ts=expire_ts,
            is_password=is_password,
            user=user,
        )
    except peewee.IntegrityError:
        raise ConflictError(user={"name": "secret names must be unique"})


def _authorize_secret(
    server_ts: datetime.datetime,
    auth_access_token_value: str,
    secret_name: str,
) -> Secret:
    access_token = _authorize_access_token(server_ts, auth_access_token_value)
    secret = Secret.select_by_name(server_ts, secret_name)
    if not secret or (secret.user.id != access_token.secret.user.id):
        raise ForbiddenError("cannot access secret")

    return secret
