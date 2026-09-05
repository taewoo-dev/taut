from __future__ import annotations

from dataclasses import dataclass, field

from taut.configuration.manifest import ModuleClassification
from taut.configuration.model import ProjectConfiguration
from taut.domain.assurance import AssuranceEvidence
from taut.domain.facts import ModuleFacts
from taut.domain.ids import ModuleId


@dataclass
class FeatureEvidenceCache:
    entries: dict[
        ModuleId, tuple[ModuleFacts, ModuleClassification | None, dict[str, set[AssuranceEvidence]]]
    ] = field(
        default_factory=lambda: dict[
            ModuleId,
            tuple[ModuleFacts, ModuleClassification | None, dict[str, set[AssuranceEvidence]]],
        ]()
    )
    config: ProjectConfiguration | None = None

    def collect(
        self,
        config: ProjectConfiguration,
        module: ModuleFacts,
        classification: ModuleClassification | None,
    ) -> dict[str, set[AssuranceEvidence]]:
        if self.config is not config and self.config != config:
            self.entries.clear()
        self.config = config
        old = self.entries.get(module.module.id)
        if old is not None and old[0] is module and old[1] == classification:
            return old[2]
        values = module_feature_evidence(config, module, classification)
        self.entries[module.module.id] = (module, classification, values)
        return values


def module_feature_evidence(
    config: ProjectConfiguration, module: ModuleFacts, classification: ModuleClassification | None
) -> dict[str, set[AssuranceEvidence]]:
    values = {name: set[AssuranceEvidence]() for name in config.assurance.features}

    def add(domain: str, kind: str, target: str, path: str) -> None:
        if domain in values:
            values[domain].add(AssuranceEvidence(domain, kind, target, path))

    code = config.policy.code
    path = module.module.path.value
    role = classification.role if classification is not None else None
    zone = classification.zone.value if classification is not None else "prod"
    if zone == "test":
        add("tests", "path", path, path)
    elif zone == "migration":
        add("migrations", "path", path, path)
    elif zone == "script":
        add("scripts", "path", path, path)
    if module.classes and role in code.dto_roles:
        add("dto", "path", path, path)
    if module.classes and role in code.snapshot_roles:
        add("snapshot", "path", path, path)
    if module.classes and role in code.model_roles:
        add("database", "path", path, path)
    for class_fact in module.classes:
        bases = {
            value
            for base in class_fact.bases
            for value in (base.written, *(symbol.value for symbol in base.symbols))
        }
        symbol = class_fact.symbol_id.value
        if any(base in {"pydantic.BaseModel", "pydantic.main.BaseModel"} for base in bases):
            add("schema", "symbol", symbol, path)
        if "Snapshot" in class_fact.name and any(
            base in {"pydantic.BaseModel", "pydantic.main.BaseModel"} for base in bases
        ):
            add("snapshot", "symbol", symbol, path)
        if any(base.endswith("Exception") or base.endswith("Error") for base in bases):
            add("exception_registry", "symbol", symbol, path)
        if class_fact.symbol_id in (code.exception_base_symbols | code.error_code_enum_symbols):
            add("exception_registry", "symbol", symbol, path)
        if any(base.endswith(".Enum") or base.endswith(".StrEnum") for base in bases):
            add("enum", "symbol", symbol, path)
    for decorator in module.decorators:
        decorator_symbol = decorator.ref.symbol
        if decorator_symbol is not None and decorator_symbol.value == "dataclasses.dataclass":
            owner = decorator.decorated_symbol.value
            if owner.endswith(("Data", "Result", "Row")):
                add("dto", "symbol", owner, path)
    for call in module.calls:
        call_symbol = (
            call.ref.symbol.value if call.ref.symbol is not None else call.ref.written_name
        )
        if call_symbol.endswith((".commit", ".rollback", ".begin")):
            add("transaction", "symbol", call_symbol, path)
        if any(
            call_symbol == prefix.value or call_symbol.startswith(f"{prefix.value}.")
            for prefix in config.policy.boundaries.external_modules
        ):
            add("external_calls", "symbol", call_symbol, path)
        if call_symbol in {"os.getenv", "os.environ.get"} or any(
            call_symbol.startswith(prefix)
            for prefix in config.policy.security.risky_symbol_prefixes
        ):
            add("security", "symbol", call_symbol, path)
    for reference in module.references:
        reference_symbol = (
            reference.ref.symbol.value
            if reference.ref.symbol is not None
            else reference.ref.written_name
        )
        if reference_symbol in {"os.environ", "os.getenv"}:
            add("security", "symbol", reference_symbol, path)
    return values
