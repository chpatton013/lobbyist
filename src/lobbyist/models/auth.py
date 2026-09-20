import datetime
from typing import Optional

import peewee

from .base import Base, ExpiryMixin
from .secret import Secret
from .user import User


class AccessToken(Base, ExpiryMixin):
    id = peewee.UUIDField(primary_key=True)
    value = peewee.CharField(max_length=255, unique=True)
    create_ts = peewee.DateTimeField()
    expire_ts = peewee.DateTimeField()
    secret = peewee.ForeignKeyField(Secret, backref="access_tokens")

    class Meta:
        indexes = (
            (("id", "create_ts", "expire_ts"), False),
            (("value", "create_ts", "expire_ts"), False),
        )

    @staticmethod
    def _select_by_value(value: str) -> peewee.ModelSelect:
        query = AccessToken.select(AccessToken, Secret, User)
        query = query.join(Secret).join(User)
        return query.where(AccessToken.value == value)

    @staticmethod
    def select_by_value(value: str) -> Optional["AccessToken"]:
        try:
            return AccessToken._select_by_value(value).get()
        except peewee.DoesNotExist:
            return None

    @staticmethod
    def select_valid_by_value(
        server_ts: datetime.datetime,
        value: str,
    ) -> Optional["AccessToken"]:
        try:
            query = AccessToken._select_by_value(value)
            query = query.where(
                AccessToken.is_valid(server_ts) & Secret.is_valid(server_ts) &
                User.is_valid(server_ts)
            )
            return query.get()
        except peewee.DoesNotExist:
            return None


class RefreshToken(Base, ExpiryMixin):
    id = peewee.UUIDField(primary_key=True)
    value = peewee.CharField(max_length=255, unique=True)
    create_ts = peewee.DateTimeField()
    expire_ts = peewee.DateTimeField()
    access_token = peewee.ForeignKeyField(AccessToken, backref="refresh_tokens")

    class Meta:
        indexes = (
            (("id", "create_ts", "expire_ts"), False),
            (("value", "create_ts", "expire_ts"), False),
        )

    @staticmethod
    def _select_by_value(value: str) -> peewee.ModelSelect:
        query = RefreshToken.select(RefreshToken, AccessToken, Secret, User)
        query = query.join(AccessToken).join(Secret).join(User)
        return query.where(RefreshToken.value == value)

    @staticmethod
    def select_by_value(value: str) -> Optional["RefreshToken"]:
        try:
            return RefreshToken._select_by_value(value).get()
        except peewee.DoesNotExist:
            return None

    @staticmethod
    def select_valid_by_value(
        server_ts: datetime.datetime,
        value: str,
    ) -> Optional["RefreshToken"]:
        try:
            query = RefreshToken._select_by_value(value)
            query = query.where(
                RefreshToken.is_valid(server_ts) &
                AccessToken.is_valid(server_ts) & Secret.is_valid(server_ts) &
                User.is_valid(server_ts)
            )
            return query.get()
        except peewee.DoesNotExist:
            return None

    def into_dict(self):
        return {
            "value": self.value,
            "create_ts": self.create_ts,
            "expire_ts": self.expire_ts,
            "access_token_value": self.access_token.value,
        }
