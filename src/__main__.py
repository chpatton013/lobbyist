#!/usr/bin/env python3

import logging

import peewee

from lobbyist.library.app import app
from lobbyist.library.db import db
from lobbyist.models import AccessToken, RefreshToken, User, Secret
from lobbyist.views import *

logger = logging.basicConfig(level=logging.DEBUG)

logging.info("creating db...")
db().initialize(
    peewee.SqliteDatabase(
        "testing.db",
        pragmas={
            "journal_mode": "wal",
            "cache_size": -1 * 64000,
            "foreign_keys": 1,
            "ignore_check_constraints": 0,
            "synchronous": 0,
        }
    )
)
db().connect()
db().create_tables([User, Secret, AccessToken, RefreshToken])

logging.info("starting app...")
app.app().run()
