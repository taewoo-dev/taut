from sqlalchemy import Column, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    posts: Mapped[list["Post"]] = relationship(back_populates="author", lazy="selectin")


class Post(Base):
    id = Column(String(36), primary_key=True)
    author = relationship("User", back_populates="posts", lazy="joined")
