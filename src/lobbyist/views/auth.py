import datetime
import logging

from ..library import app, error, validation
from ..controllers import auth

APP = app.app()


@APP.route("/auth/access", methods=["POST"])
def create_access_token():
    logging.debug("views.auth.create_access_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    secret_name = validation.required_field_username("name")
    secret_plain = validation.required_field_secret("secret")
    access_token_lifetime = validation.optional_field_access_token_lifetime(
        "access_token_lifetime"
    )
    refresh_token_lifetime = validation.optional_field_refresh_token_lifetime(
        "refresh_token_lifetime"
    )

    response = auth.create_access_token(
        create_ts=server_ts,
        secret_name=secret_name,
        secret_value=secret_plain,
        access_token_lifetime=access_token_lifetime,
        refresh_token_lifetime=refresh_token_lifetime,
    )

    return (response.into_dict(), 201)


@APP.route("/auth/access/<access_token>", methods=["GET"])
def read_access_token(access_token_value: str):
    logging.debug("views.auth.read_access_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()

    response = auth.read_access_token(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        access_token_value=access_token_value,
    )

    return (response.into_dict(), 200)


@APP.route("/auth/access/<access_token>", methods=["PATCH"])
def update_access_token(access_token_value: str):
    logging.debug("views.auth.update_access_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()
    expire_ts = validation.optional_field_expire_ts("expire_ts")

    response = secret.update_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        access_token_value=access_token_value,
        expire_ts=expire_ts,
    )

    return (response.into_dict(), 200)


@APP.route("/auth/access/<access_token>", methods=["DELETE"])
def delete_access_token(access_token_value: str):
    logging.debug("views.auth.delete_access_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()

    response = secret.delete_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        access_token_value=access_token_value,
    )

    return (response.into_dict(), 200)


@APP.route("/auth/refresh", methods=["POST"])
def refresh_access_token():
    logging.debug("views.auth.refresh_access_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()
    access_token_lifetime = validation.optional_field_access_token_lifetime(
        "access_token_lifetime"
    )
    refresh_token_lifetime = validation.optional_field_refresh_token_lifetime(
        "refresh_token_lifetime"
    )

    response = auth.refresh_access_token(
        create_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        access_token_lifetime=access_token_lifetime,
        refresh_token_lifetime=refresh_token_lifetime,
    )

    return (response.into_dict(), 201)


@APP.route("/auth/refresh/<refresh_token>", methods=["GET"])
def read_refresh_token(refresh_token_value: str):
    logging.debug("views.auth.read_refresh_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()

    response = auth.read_access_token(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        refresh_token_value=refresh_token_value,
    )

    return (response.into_dict(), 200)


@APP.route("/auth/refresh/<refresh_token>", methods=["PATCH"])
def update_refresh_token(refresh_token_value: str):
    logging.debug("views.auth.update_refresh_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()
    expire_ts = validation.optional_field_expire_ts("expire_ts")

    response = secret.update_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        refresh_token_value=refresh_token_value,
        expire_ts=expire_ts,
    )

    return (response.into_dict(), 200)


@APP.route("/auth/refresh/<refresh_token>", methods=["DELETE"])
def delete_refresh_token(refresh_token_value: str):
    logging.debug("views.auth.delete_refresh_token")

    server_ts = datetime.datetime.utcnow()

    validation.validate_accept()
    auth_access_token_value = validation.validate_authentication_bearer()

    response = secret.delete_secret(
        server_ts=server_ts,
        auth_access_token_value=auth_access_token_value,
        refresh_token_value=refresh_token_value,
    )

    return (response.into_dict(), 200)
