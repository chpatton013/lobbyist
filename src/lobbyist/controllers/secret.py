import datetime
import logging
import uuid
from typing import Any, Mapping, Optional, Tuple

import peewee

from ..library import crypto, db, validation
from ..library.config import Range, config
from ..library.error import ConflictError, ForbiddenError
from ..models.auth import AccessToken
from ..models.secret import Secret
from ..models.user import User

DB = db.db()

# TODO: make into_dict_transitive functions for all models
# consider pulling into_dict out of the model and putting it where ever the
# transitive version goes. it can't go on the model because there would be a
# recursive import between them.
# maybe make a "responses" module for these?
# will probably also want to make a "factory" module then.


class CreateSecretResponse:
    def __init__(self, secret: Secret, value: str):
        self.secret = secret
        self.value = value

    def into_dict(self):
        return {
            "secret": self.secret.into_dict(self.value),
        }


class ReadSecretResponse:
    def __init__(self, secret: Secret):
        self.secret = secret

    def into_dict(self):
        return {
            "secret": self.secret.into_dict(),
        }


@DB.atomic()
def create_secret(
    create_ts: datetime.datetime,
    access_token_value: str,
    expire_ts: Optional[datetime.datetime],
) -> CreateSecretResponse:
    logging.debug("controllers.secret.create_secret")

    access_token = AccessToken.select_valid_by_value(
        create_ts,
        access_token_value,
    )
    if not access_token:
        raise ForbiddenError("token is not authorized")

    secret_name = crypto.make_secret_string(config().secret_name_entropy)
    secret_plain = crypto.make_secret_string(config().secret_value_entropy)
    secret_hash = crypto.hash_secret(secret_plain)

    secret = _create_secret(
        secret_name,
        secret_hash,
        create_ts,
        expire_ts,
        access_token.secret.user,
    )

    return CreateSecretResponse(secret, secret_plain)


@DB.atomic()
def read_secret(
    server_ts: datetime.datetime,
    name: str,
    access_token_value: Optional[str],
) -> ReadSecretResponse:
    logging.debug("controllers.secret.read_secret")

    secret, _, authorized = _authorize(server_ts, name, access_token_value)

    if not authorized:
        raise ForbiddenError("cannot read secret")

    return ReadSecretResponse(secret)


@DB.atomic()
def update_secret(
    server_ts: datetime.datetime, name: str, access_token_value: str,
    **fields: Mapping[str, Any]
) -> ReadSecretResponse:
    logging.debug("controllers.secret.update_secret")

    secret, _, authorized = _authorize(server_ts, name, access_token_value)

    if not authorized:
        raise ForbiddenError("cannot update secret")

    if "value" in fields:
        if name != secret.user.name:
            raise BadRequestError(
                "cannot change secret",
                fields={"value": "secret value must not be set"},
            )

            value = fields["value"]
            validation.validate_secret("value", value)

            secret.hash = crypto.hash_secret(secret_plain)

    if "expire_ts" in fields:
        if name == secret.user.name:
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

    return ReadSecretResponse(secret)


@DB.atomic()
def delete_secret(
    server_ts: datetime.datetime,
    name: str,
    access_token_value: str,
) -> ReadSecretResponse:
    logging.debug("controllers.secret.update_secret")

    secret, _, authorized = _authorize(server_ts, name, access_token_value)

    if not authorized:
        raise ForbiddenError("cannot update secret")

    secret.expire_ts = expire_ts
    secret.save()

    return ReadSecretResponse(secret)


def _create_secret(
    name: str,
    hash: str,
    create_ts: datetime.datetime,
    expire_ts: Optional[datetime.datetime],
    user: User,
) -> Secret:
    logging.debug("controllers.secret._create_secret")

    try:
        return Secret.create(
            id=uuid.uuid4(),
            name=name,
            hash=hash,
            create_ts=create_ts,
            expire_ts=expire_ts,
            user=user,
        )
    except peewee.IntegrityError:
        raise ConflictError(user={"name": "secret names must be unique"})


def _authorize(
    server_ts: datetime.datetime,
    name: str,
    access_token_value: str,
) -> Tuple[Optional[Secret], Optional[AccessToken], bool]:
    secret = Secret.select_by_name(server_ts, name)

    if access_token_value is None:
        access_token = None
    else:
        access_token = AccessToken.select_valid_by_value(
            server_ts,
            access_token_value,
        )

    authorized = secret and access_token and (
        secret.id == access_token.secret.id
    )

    return (user, access_token, authorized)
