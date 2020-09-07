import base64
import binascii
import datetime
from typing import Optional, Tuple

import flask

from .config import Range, config
from .error import BadRequestError, NotAcceptableError, UnauthorizedError


def validate_accept() -> None:
    context = {}

    if (
        flask.request.accept_mimetypes and
        (config().content_mimetype not in flask.request.accept_mimetypes)
    ):
        context["mimetype"] = f"need mimetype: {config().content_mimetype}"

    if (
        flask.request.accept_encodings and any(
            encoding not in flask.request.accept_encodings
            for encoding in config().content_encodings
        )
    ):
        context["encoding"] = "need encodings: {}".format(
            ", ".join(config().content_encodings)
        )

    if (
        flask.request.accept_charsets and
        (config().content_charset not in flask.request.accept_charsets)
    ):
        context["charset"] = f"need charset: {config().content_charset}"

    if (
        flask.request.accept_languages and
        (config().content_language not in flask.request.accept_languages)
    ):
        context["language"] = f"need language: {config().content_language}"

    if context:
        raise NotAcceptableError(**context)


def validate_authentication_basic() -> Tuple[str, bytes]:
    method, payload = _parse_authorization_header()
    if method != "basic":
        raise BadRequestError(
            "invalid credentials",
            headers={
                "authorization": "must provide valid credentials for basic-auth"
            },
        )
    return _parse_authentication_basic(payload)


def validate_authentication_bearer() -> str:
    method, payload = _parse_authorization_header()
    if method != "bearer":
        raise BadRequestError(
            "invalid credentials",
            headers={
                "authorization": "must provide a valid token for bearer-auth"
            },
        )
    return payload


def required_field_username(key: str) -> str:
    name = flask.request.form.get(key, "")

    if not name:
        raise BadRequestError(
            "missing username",
            fields={key: "must provide username"},
        )

    if not config().username_length.contains(len(name)):
        raise BadRequestError(
            "invalid username",
            fields={
                key:
                    "username length must be between {}".format(
                        config().username_length
                    )
            },
        )

    if not set(name).issubset(config().username_valid_characters):
        raise BadRequestError(
            "invalid username",
            fields={
                key:
                    "username must only contain valid characters: {}".format(
                        config().username_valid_characters
                    ),
            },
        )

    return name


def required_field_secret(key: str) -> str:
    secret = flask.request.form.get(key, "")

    if not secret:
        raise BadRequestError(
            "missing secret",
            fields={key: "must provide secret"},
        )

    validate_secret(key, secret)

    return secret


def optional_field_expire_ts(key: str) -> Optional[datetime.datetime]:
    expire_ts = flask.request.form.get(key, "")
    if not expire_ts:
        return None

    try:
        expire_ts_s = int(expire_ts)
    except ValueError:
        raise BadRequestError(
            "invalid expire time",
            fields={
                key: "expire time must be an integer number of seconds",
            },
        )

    try:
        return datetime.datetime.utcfromtimestamp(expire_ts_s)
    except (OverflowError, OSError):
        raise BadRequestError(
            "invalid expire time",
            fields={
                key: "expire time must within range of gmtime()",
            },
        )

    return expire_ts_dt


def validate_secret(key: str, secret: str):
    if len(secret) < config().password_length_min:
        raise BadRequestError(
            "invalid secret",
            fields={
                key:
                    f"secret length must be at least {config().password_length_min}"
            },
        )


def validate_expire_time(
    key: str, expire_ts: datetime.datetime, allowed_range: Range
):
    if not allowed_range.contains(expire_ts):
        raise BadRequestError(
            "invalid expire time",
            fields={
                key: f"expire time must be between {allowed_range}",
            },
        )


def optional_field_access_token_lifetime(
    key: str,
) -> Optional[datetime.timedelta]:
    return _optional_field_token_lifetime(key, config().access_token_lifetime)


def optional_field_refresh_token_lifetime(
    key: str,
) -> Optional[datetime.timedelta]:
    return _optional_field_token_lifetime(key, config().refresh_token_lifetime)


def _parse_authorization_header() -> Tuple[str, str]:
    try:
        authorization = flask.request.headers["authorization"]
    except KeyError:
        raise UnauthorizedError("missing authorization header")

    method, _, payload = authorization.strip().partition(" ")
    return (method.lower(), payload)


def _parse_authentication_basic(payload) -> Tuple[str, bytes]:
    try:
        username, _, password = base64.b64decode(payload).partition(b":")
        username = username.decode()
    except (binascii.Error, UnicodeError):
        raise BadRequestError(
            "invalid credentials",
            headers={
                "authorization": "must provide valid credentials for basic-auth"
            },
        )

    return (username, passowrd)


def _optional_field_token_lifetime(
    key: str,
    config_lifetime: Range,
) -> Optional[datetime.timedelta]:
    token_lifetime = flask.request.form.get(key)
    if not token_lifetime:
        return config_lifetime.default

    try:
        token_lifetime_s = int(token_lifetime)
    except ValueError:
        raise BadRequestError(
            "invalid lifetime",
            fields={
                key: "lifetime must be an integer number of seconds",
            },
        )

    token_lifetime_td = datetime.timedelta(seconds=token_lifetime_s)
    if not config_lifetime.contains(token_lifetime_td):
        raise BadRequestError(
            "invalid lifetime",
            fields={
                key: f"lifetime must be between {config_lifetime}",
            },
        )

    return token_lifetime_td
