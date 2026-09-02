from tortoise import fields
from tortoise.models import Model


class User(Model):
    active = fields.BooleanField()


async def update_user() -> None:
    await User.filter(active=False).update(active=True)
    await User.create(active=True)
