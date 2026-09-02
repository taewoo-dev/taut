from tortoise import fields
from tortoise.models import Model
from tortoise.transactions import atomic


class User(Model):
    active = fields.BooleanField()


@atomic()
async def update_user() -> None:
    await User.filter(active=False).update(active=True)
    await User.create(active=True)
