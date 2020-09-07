import datetime

import peewee

from ..library.db import db


class Base(peewee.Model):
    class Meta:
        database = db()


class ExpiryMixin:
    def is_valid(self, server_ts: datetime.datetime):
        return (self.create_ts <= server_ts <= self.expire_ts)

    @classmethod
    def where_valid(cls, server_ts: datetime.datetime):
        return (cls.create_ts <= server_ts <= cls.expire_ts)


class OptionallyExpiryMixin:
    def is_valid(self, server_ts: datetime.datetime):
        return ((self.create_ts <= server_ts) and
                (self.expire_ts is None or (server_ts <= self.expire_ts)))

    @classmethod
    def where_valid(cls, server_ts: datetime.datetime):
        return ((cls.create_ts <= server_ts) &
                (cls.expire_ts.is_null() | (server_ts <= cls.expire_ts)))
