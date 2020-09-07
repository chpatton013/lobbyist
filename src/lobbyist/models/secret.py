import datetime
from typing import Optional

import peewee

from .base import Base, OptionallyExpiryMixin
from .user import User


class Secret(Base, OptionallyExpiryMixin):
    id = peewee.UUIDField(primary_key=True)
    name = peewee.CharField(max_length=255, unique=True)
    hash = peewee.CharField(max_length=255)
    create_ts = peewee.DateTimeField()
    expire_ts = peewee.DateTimeField(null=True)
    user = peewee.ForeignKeyField(User, backref="secrets")

    class Meta:
        indexes = (
            (("id", "create_ts", "expire_ts"), False),
            (("name", "create_ts", "expire_ts"), False),
        )

    @staticmethod
    def _select_by_name(name: str) -> peewee.ModelSelect:
        return Secret.select(Secret, User).join(User).where(Secret.name == name)

    @staticmethod
    def select_by_name(name: str) -> Optional["Secret"]:
        try:
            return Secret._select_by_name(name).get()
        except peewee.DoesNotExist:
            return None

    @staticmethod
    def select_valid_by_name(
        server_ts: datetime.datetime,
        name: str,
    ) -> Optional["Secret"]:
        try:
            return Secret._select_by_name(name).where(
                Secret.is_valid(server_ts) & User.is_valid(server_ts)
            ).get()
        except peewee.DoesNotExist:
            return None

    def into_dict(self, value: Optional[str] = None):
        as_dict = {
            "name": self.name,
            "create_ts": self.create_ts,
            "user_name": self.user.name,
        }
        if self.expire_ts is not None:
            as_dict["expire_ts"] = self.expire_ts
        if value is not None:
            as_dict["value"] = value
        return as_dict
