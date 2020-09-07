import flask

import .validation
from .config import config
from .error import BadRequestError, UnauthorizedError, NotAcceptableError

from .views import *







@APP.route("/secret", methods=["POST"])
def create_secret():
    # Accept: application/json
    # Authentication: Bearer ACCESS_TOKEN

    # HTTP/1.1 201 Created
    # Content-Type: application/json;charset=UTF-8
    #
    # secret:
    #   name: NAME
    #   value: VALUE
    pass


@APP.route("/secret/{name}", methods=["PATCH"])
def update_secret(name):
    # Accept: application/json
    # Authentication: Bearer ACCESS_TOKEN

    # HTTP/1.1 204 No Content
    # Content-Type: application/json;charset=UTF-8
    pass


@APP.route("/secret/{name}", methods=["DELETE"])
def delete_secret(name):
    # Accept: application/json
    # Authentication: Bearer ACCESS_TOKEN
    #
    # value: VALUE
    # expire_ts: EXPIRE_TS

    # HTTP/1.1 204 No Content
    # Content-Type: application/json;charset=UTF-8
    pass


@APP.route("/access", methods=["POST"])
def create_access_token():
    username, password = verify_authorization_basic()
    print(username, password)
    # Accept: application/json
    # Authentication: Basic B64==

    # HTTP/1.1 201 Created
    # Content-Type: application/json;charset=UTF-8
    #
    # access_token:
    #   id: ID
    #   create_ts: CREATE_TS
    #   expire_ts: EXPIRE_TS
    # refresh_token:
    #   id: ID
    #   create_ts: CREATE_TS
    #   expire_ts: EXPIRE_TS
    pass


@APP.route("/refresh", methods=["POST"])
def refresh():
    # Accept: application/json
    # Authentication: Bearer REFRESH_TOKEN

    # HTTP/1.1 201 Created
    # Content-Type: application/json;charset=UTF-8
    #
    # access_token:
    #   id: ID
    #   create_ts: CREATE_TS
    #   expire_ts: EXPIRE_TS
    # refresh_token:
    #   id: ID
    #   create_ts: CREATE_TS
    #   expire_ts: EXPIRE_TS
    pass
