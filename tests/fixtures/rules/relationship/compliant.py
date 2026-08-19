from sqlalchemy.orm import relationship

items = relationship(lazy="raise_on_sql")
