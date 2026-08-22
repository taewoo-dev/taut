from __future__ import annotations

import hashlib
from collections.abc import MutableMapping

from taut.domain.facts import FactKind
from taut.domain.ids import FactId, SymbolId


def next_fact_id(
    module: str,
    scope: SymbolId | None,
    kind: FactKind,
    subject: str,
    occurrences: MutableMapping[tuple[str, str, str], int],
) -> FactId:
    scope_name = scope.value if scope else module
    key = (scope_name, kind.value, subject)
    occurrence = occurrences[key]
    occurrences[key] += 1
    raw = "\0".join((module, scope_name, kind.value, subject, str(occurrence)))
    return FactId(hashlib.sha256(raw.encode()).hexdigest())
