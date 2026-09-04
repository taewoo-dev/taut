from sqlalchemy.orm import DeclarativeBase, Mapped, relationship


class Base(DeclarativeBase):
    pass


class Item(Base):
    __tablename__ = "item"
    items: Mapped[list["Item"]] = relationship()
