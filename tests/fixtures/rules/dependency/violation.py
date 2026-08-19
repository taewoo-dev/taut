from fastapi import Depends


def run(client: object = Depends()) -> object:
    return client
