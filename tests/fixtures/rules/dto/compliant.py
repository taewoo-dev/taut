from dataclasses import dataclass


@dataclass(frozen=True)
class UserData:
    tags: tuple[str, ...]
