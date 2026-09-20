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
    auth_access_token_value = validation.validate_authentication_bearer()
    expire_ts = validation.optional_field_expire_ts("expire_ts")

    response = secret.create_secret(
        create_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        expire_ts=expire_ts,
    )

    return (response.into_dict(), 201)


@APP.route("/secret/<name>", methods=["GET"])
def read_secret(secret_name: str):
    logging.debug("views.secret.read_secret")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()

    response = secret.read_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        secret_name=secret_name,
    )

    return (response.into_dict(), 200)


@APP.route("/secret", methods=["PATCH"])
def update_secret():
    logging.debug("views.secret.update_secret")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()
    secret_value = validation.optional_field_expire_ts("value")
    expire_ts = validation.optional_field_expire_ts("expire_ts")

    response = secret.update_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        secret_value=secret_value,
        expire_ts=expire_ts,
    )

    return (response.into_dict(), 200)


@APP.route("/secret/<name>", methods=["DELETE"])
def delete_secret(secret_name: str):
    logging.debug("views.secret.delete_secret")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()

    response = secret.delete_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        secret_name=secret_name,
    )

    return (response.into_dict(), 200)
