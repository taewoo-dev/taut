from dataclasses import dataclass


@dataclass(frozen=True)
class UserData:
    name: str
