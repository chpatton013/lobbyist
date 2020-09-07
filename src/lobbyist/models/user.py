from typing import Optional

import peewee

from .base import Base, OptionallyExpiryMixin


class User(Base, OptionallyExpiryMixin):
    id = peewee.UUIDField(primary_key=True)
    name = peewee.CharField(max_length=255, unique=True)
    create_ts = peewee.DateTimeField()
    expire_ts = peewee.DateTimeField(null=True)

    class Meta:
        indexes = (
            (("id", "create_ts", "expire_ts"), False),
            (("name", "create_ts", "expire_ts"), False),
        )

    @staticmethod
    def select_by_name(name: str) -> Optional["User"]:
        try:
            return User.select().where(User.name == name).get()
        except peewee.DoesNotExist:
            return None

    def into_dict(self):
        as_dict = {
            "id": self.id,
            "name": self.name,
            "create_ts": self.create_ts,
        }
        if self.expire_ts is not None:
            as_dict["expire_ts"] = self.expire_ts
        return as_dict
