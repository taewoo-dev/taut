from app.repository import read_greeting


def get_greeting() -> str:
    return read_greeting()
