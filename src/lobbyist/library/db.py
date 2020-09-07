import logging
import time
from typing import Any, Callable

import peewee

from .config import config

__SINGLETON: peewee.Database = peewee.DatabaseProxy()


def db() -> peewee.Database:
    global __SINGLETON
    return __SINGLETON


def txn(fn: Callable[[], Any]) -> Any:
    logging.debug("db.txn")

    with db().atomic() as _:
        return fn()


def retry_txn(
    fn: Callable[[], Any],
    count: int = config().db_retry_count_default,
    delay_ms: float = config().db_retry_delay_ms_default,
) -> Any:
    logging.debug("db.retry_txn %d %f", count, delay_ms)

    return __retry(fn, 0, count, delay_ms)


def __should_retry(index: int, count: int, delay_ms: float) -> bool:
    if delay_ms > 0:
        time.sleep(2**index * (delay_ms / 1e6))
    return (index + 1) < count


def __retry(
    fn: Callable[[], Any],
    index: int,
    count: int,
    delay_ms: float,
) -> Any:
    try:
        return txn(fn)
    except peewee.PeeweeException as error:
        logging.debug("%s", error)
        if __should_retry(index, count, delay_ms):
            return __retry(fn, index + 1, count, delay_ms)
        raise
