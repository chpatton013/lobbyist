import flask

from .error import HttpError

__SINGLETON = flask.Flask(__name__)


def app():
    global __SINGLETON
    return __SINGLETON


@__SINGLETON.errorhandler(HttpError)
def handle_http_error(error):
    return error.into_response()
