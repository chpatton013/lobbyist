import datetime
import logging

from ..library import app, error, validation
from ..controllers import user

APP = app.app()


@APP.route("/user", methods=["POST"])
def create_user():
    logging.debug("views.user.create_user")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    name = validation.required_field_username("name")
    secret = validation.required_field_secret("secret")
    access_token_lifetime = validation.optional_field_access_token_lifetime(
        "access_token_lifetime"
    )
    refresh_token_lifetime = validation.optional_field_refresh_token_lifetime(
        "refresh_token_lifetime"
    )

    response = user.create_user(
        create_ts=server_ts,
        name=name,
        secret_plain=secret,
        access_token_lifetime=access_token_lifetime,
        refresh_token_lifetime=refresh_token_lifetime,
    )

    return (response.into_dict(), 201)


@APP.route("/user/<name>", methods=["GET"])
def read_user(name: str):
    logging.debug("views.user.read_user")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    try:
        access_token = validation.validate_authentication_bearer()
    except error.UnauthorizedError:
        access_token = None

    response = user.read_user(
        server_ts=server_ts,
        name=name,
        access_token_value=access_token,
    )

    return (response.into_dict(), 200)


@APP.route("/user/<name>", methods=["PATCH"])
def update_user(name: str):
    logging.debug("views.user.update_user")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    access_token = validation.validate_authentication_bearer()
    expire_ts = validation.optional_field_expire_ts("expire_ts")

    response = user.update_user(
        server_ts=server_ts,
        name=name,
        access_token_value=access_token,
        expire_ts=expire_ts,
    )

    return (response.into_dict(), 200)


@APP.route("/user/<name>", methods=["DELETE"])
def delete_user(name: str):
    logging.debug("views.user.delete_user")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    access_token = validation.validate_authentication_bearer()

    response = user.delete_user(
        server_ts=server_ts,
        name=name,
        access_token_value=access_token,
    )

    return (response.into_dict(), 200)
