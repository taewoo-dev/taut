from fastapi import Depends


def route(user: object = Depends()) -> object:
    return user
