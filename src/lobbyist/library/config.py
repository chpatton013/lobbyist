import datetime
import string
from typing import Generic, Optional, TypeVar


T = TypeVar["T"]


class Range(Generic[T]):
    def __init__(self, min: Optional[T], max: Optional[T]):
        self.min = min
        self.max = max

    def __str__(self):
        return f"[{self.min}; {self.max}]"

    def contains(self, value: T) -> bool:
        if self.min is None and self.max is None:
            return True
        elif self.min is None:
            return value <= self.max
        elif self.max is None:
            return self.min <= value
        else:
            return self.min <= value <= self.max


class RangeWithDefault(Range[T]):
    def __init__(self, min: Optional[T], max: Optional[T], default: T):
        super().__init__(min, max)
        self.default = default

    def __str__(self):
        return f"[{self.min}; {self.max}] (default: {self.default})"


# TODO: Load this from a file
class Config:
    content_mimetype = "application/json"
    content_encodings = ["gzip"]
    content_charset = "utf-8"
    content_language = "en-US"

    db_retry_count_default = 3
    db_retry_delay_ms_default = 10.0

    username_length = Range[int](4, 64)
    username_valid_characters = set(
        string.ascii_letters + string.digits + "_-."
    )

    password_length_min = 8

    secret_name_entropy = 24
    secret_value_entropy = 128
    secret_bcrypt_cost = 12

    access_token_lifetime = RangeWithDefault[datetime.timedelta](
        min=datetime.timedelta(hours=1),
        max=datetime.timedelta(days=3),
        default=datetime.timedelta(days=1),
    )
    access_token_entropy = 128

    refresh_token_lifetime = RangeWithDefault[datetime.timedelta](
        min=datetime.timedelta(hours=1),
        max=datetime.timedelta(weeks=2),
        default=datetime.timedelta(weeks=1),
    )
    refresh_token_entropy = 128


__SINGLETON = Config()


def config():
    global __SINGLETON
    return __SINGLETON
