"""
POST    /secret         [['expire_ts']]
GET     /secret/<name>
PATCH   /secret/<name>  [['value' if password; 'expire_ts' if not password]]
DELETE  /secret/<name>  [[if not password]]
"""

import datetime
import logging

from ..library import app, config, error, validation
from ..controllers import secret

APP = app.app()


@APP.route("/secret", methods=["POST"])
def create_secret():
    logging.debug("views.secret.create_secret")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    access_token = validation.validate_authentication_bearer()
    expire_ts = validation.optional_field_expire_ts("expire_ts")

    response = secret.create_secret(
        create_ts=server_ts,
        access_token_value=access_token,
        expire_ts=expire_ts,
    )

    return (response.into_dict(), 201)


@APP.route("/secret/<name>", methods=["GET"])
def read_secret(name: str):
    logging.debug("views.secret.read_secret")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    access_token = validation.validate_authentication_bearer()

    response = secret.read_secret(
        server_ts=server_ts,
        name=name,
        access_token_value=access_token,
    )

    return (response.into_dict(), 200)
