from __future__ import annotations

from taut.domain.evaluations import RuleLevel
from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId

BUILTIN_RULE_LEVELS = FrozenMap(
    (RuleId(value), RuleLevel.ADVISORY if value == "CAT001" else RuleLevel.ENFORCED)
    for value in (
        "ARCH000",
        "TIME001",
        "TX001",
        "SESSION001",
        "SESSION002",
        "SESSION003",
        "IMPORT001",
        "SIZE001",
        "BOUNDARY001",
        "BOUNDARY002",
        "BOUNDARY003",
        "ADAPTER001",
        "ENTRY001",
        "SERVICE001",
        "QUERY001",
        "MODEL001",
        "WIRING001",
        "ADAPTER002",
        "DEPENDS001",
        "CONFIG001",
        "TEST001",
        "TEST002",
        "HTTP001",
        "LOG001",
        "ARCH001",
        "ARCH002",
        "IMPORT002",
        "RUNTIME001",
        "TX002",
        "ASYNC001",
        "SEC001",
        "CAT001",
        "DTO001",
        "DTO002",
        "SNAPSHOT001",
        "SCHEMA001",
        "SCHEMA002",
        "SCHEMA003",
        "API001",
        "API002",
        "API003",
        "ENUM001",
        "ORM001",
        "ORM002",
        "DB001",
        "SQL001",
        "EXC001",
        "IGNORE001",
    )
)

__all__ = ["BUILTIN_RULE_LEVELS"]
