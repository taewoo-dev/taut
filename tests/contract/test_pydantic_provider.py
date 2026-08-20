from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.pydantic import (
    PYDANTIC_CONFIGS,
    PYDANTIC_FIELDS,
    PYDANTIC_MODELS,
    PYDANTIC_OPERATIONS,
    PYDANTIC_SERIALIZERS,
    PYDANTIC_VALIDATORS,
    PydanticConfigFact,
    PydanticFieldFact,
    PydanticModelFact,
    PydanticOperationFact,
    PydanticProvider,
    PydanticValidatorFact,
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
    class Config:
        orm_mode = True
        extra = 'forbid'
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
def construct(data): return User(data)
def dump(model: User): return model.model_dump(by_alias=True)
def arbitrary(value): return value.dict()
def arbitrary_dump(value): return value.model_dump()
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
    configs = cast(tuple[PydanticConfigFact, ...], result.capabilities[PYDANTIC_CONFIGS])
    assert configs
    v1 = next(item for item in configs if item.kind == "v1")
    assert {name for name, _ in v1.options} >= {"orm_mode", "extra"}
    assert all(value.literal_value in {"True", "'forbid'"} for _, value in v1.options)
    assert result.capabilities[PYDANTIC_VALIDATORS]
    assert result.capabilities[PYDANTIC_SERIALIZERS]
    operations = cast(tuple[PydanticOperationFact, ...], result.capabilities[PYDANTIC_OPERATIONS])
    assert {item.operation for item in operations} >= {
        "model_validate",
        "model_dump",
        "parse_obj",
        "from_orm",
        "construct",
    }
    assert not any(
        item.call.ref.written_name in {"value.dict", "value.model_dump"} for item in operations
    )
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


def test_pydantic_direct_field_and_configdict_aliases_exclude_wrappers() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from pydantic import BaseModel, ConfigDict, Field as PublicField
def wrapper(value): return value
class Model(BaseModel):
    direct: int = PublicField(alias='direct-id')
    wrapped: int = wrapper(PublicField(alias='wrapped-id'))
    model_config = ConfigDict(extra='forbid')
    bad_config = wrapper(ConfigDict(extra='allow'))
""",
        )
    )
    result = apply_fact_providers(snapshot, (PydanticProvider(),))
    fields = cast(tuple[PydanticFieldFact, ...], result.capabilities[PYDANTIC_FIELDS])
    assert {item.name for item in fields} == {"direct", "wrapped"}
    assert next(item for item in fields if item.name == "direct").declaration_ref is not None
    assert next(item for item in fields if item.name == "wrapped").declaration_ref is None
    configs = cast(tuple[PydanticConfigFact, ...], result.capabilities[PYDANTIC_CONFIGS])
    assert len(configs) == 1
    assert configs[0].kind == "v2"


def test_pydantic_v1_and_v2_validator_families_are_kept() -> None:
    snapshot = analyze(
        make_source(
            "app/validators.py",
            """from pydantic import (
    BaseModel, field_validator, model_validator, root_validator, validator
)
class Model(BaseModel):
    value: int
    @validator('value')
    def old_field(cls, value): return value
    @root_validator
    def old_root(cls, values): return values
    @field_validator('value')
    @classmethod
    def new_field(cls, value): return value
    @model_validator(mode='after')
    def new_model(self): return self
""",
        )
    )
    result = apply_fact_providers(snapshot, (PydanticProvider(),))
    validators = cast(tuple[PydanticValidatorFact, ...], result.capabilities[PYDANTIC_VALIDATORS])
    assert {item.decorator for item in validators} >= {
        "validator",
        "root_validator",
        "field_validator",
        "model_validator",
    }
