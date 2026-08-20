from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.pydantic import (
    PYDANTIC_CONFIGS,
    PYDANTIC_FIELDS,
    PYDANTIC_MODELS,
    PYDANTIC_OPERATIONS,
    PYDANTIC_SERIALIZERS,
    PYDANTIC_VALIDATORS,
    PydanticFieldFact,
    PydanticModelFact,
    PydanticOperationFact,
    PydanticProvider,
)
from taut.analysis.providers import apply_fact_providers


def test_pydantic_provider_extracts_v1_v2_semantics_and_operations() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from pydantic import (
    BaseModel, ConfigDict, Field, computed_field, field_serializer, field_validator
)
class Base(BaseModel):
    class Config: orm_mode = True
class User(Base):
    model_config = ConfigDict(populate_by_name=True)
    user_id: int = Field(
        default=0, alias='id', validation_alias='userId', serialization_alias='uid'
    )
    name: str
    @field_validator('name')
    @classmethod
    def valid(cls, value): return value
    @computed_field
    @property
    def label(self): return self.name
    @field_serializer('name')
    def serial(self, value): return value
def build(data): return User.model_validate(data)
def dump(model): return model.model_dump(by_alias=True)
def old(data): return User.parse_obj(data)
""",
        ),
        make_source(
            "app/other.py",
            "from app.models import User\ndef make(data): return User.from_orm(data)",
        ),
    )
    result = apply_fact_providers(snapshot, (PydanticProvider(),))
    assert len(result.capabilities[PYDANTIC_MODELS]) == 2
    fields = cast(tuple[PydanticFieldFact, ...], result.capabilities[PYDANTIC_FIELDS])
    assert len(fields) == 2
    user_id = next(item for item in fields if item.name == "user_id")
    assert user_id.alias is not None
    assert user_id.annotation_ref is not None
    assert result.capabilities[PYDANTIC_CONFIGS]
    assert result.capabilities[PYDANTIC_VALIDATORS]
    assert result.capabilities[PYDANTIC_SERIALIZERS]
    operations = cast(tuple[PydanticOperationFact, ...], result.capabilities[PYDANTIC_OPERATIONS])
    assert {item.operation for item in operations} >= {
        "model_validate",
        "model_dump",
        "parse_obj",
        "from_orm",
    }
    assert all(item.call.provenance.source_hash for item in operations)


def test_pydantic_provider_does_not_classify_nested_or_unknown_models() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from pydantic import BaseModel
class Outer:
    class Fake:
        value: int
class Good(BaseModel): pass
class Unknown(UnknownBase): pass
""",
        )
    )
    result = apply_fact_providers(snapshot, (PydanticProvider(),))
    models = cast(tuple[PydanticModelFact, ...], result.capabilities[PYDANTIC_MODELS])
    symbols = {item.symbol.value for item in models}
    assert symbols == {"app.models.Good"}
