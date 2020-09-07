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
        return AccessToken.select(AccessToken, Secret,
                                  User).join(Secret).join(User).where(
                                      AccessToken.value == value
                                  )

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
            return AccessToken._select_by_value(value).where(
                AccessToken.is_valid(server_ts) & Secret.is_valid(server_ts) &
                User.is_valid(server_ts)
            ).get()
        except peewee.DoesNotExist:
            return None

    def into_dict(self):
        return {
            "value": self.value,
            "create_ts": self.create_ts,
            "expire_ts": self.expire_ts,
            "secret_name": self.secret.name,
        }


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
        return RefreshToken.select(RefreshToken, AccessToken, Secret,
                                   User).join(AccessToken
                                              ).join(Secret).join(User).where(
                                                  RefreshToken.value == value
                                              )

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
            return RefreshToken._select_by_value(value).where(
                RefreshToken.is_valid(server_ts) &
                AccessToken.is_valid(server_ts) & Secret.is_valid(server_ts) &
                User.is_valid(server_ts)
            ).get()
        except peewee.DoesNotExist:
            return None

    def into_dict(self):
        return {
            "value": self.value,
            "create_ts": self.create_ts,
            "expire_ts": self.expire_ts,
            "access_token_value": self.access_token.value,
        }
