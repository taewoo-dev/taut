"""Census the strong object graph reachable from a resident check session.

This is not RSS or a complete allocation measurement: managed instance dictionaries,
allocator overhead, and process globals excluded from the graph are not fully counted.
Use the same Python and script with PYTHONPATH selecting each engine to compare counts.
Target source is read for static analysis only. A single worker avoids pickle variation.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import platform
import sys
import types
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import taut
from taut.check_service import CheckRequest, ResidentCheckSession

_VALUE_TYPES = frozenset(
    {
        "taut.domain.ids.SymbolId",
        "taut.domain.location.SourceRange",
        "taut.domain.provenance.Provenance",
        "taut.domain.facts.SyntaxContext",
        "taut.policy.function_summaries.FunctionSemanticSummary",
        "builtins.frozenset",
    }
)


def census(root: object) -> dict[str, object]:
    seen: set[int] = set()
    pending: list[object] = [root]
    counts: Counter[str] = Counter()
    sizes: Counter[str] = Counter()
    values: dict[str, set[object]] = {}
    excluded = (
        type,
        types.ModuleType,
        types.FunctionType,
        types.BuiltinFunctionType,
        types.CodeType,
    )
    while pending:
        item = pending.pop()
        identity = id(item)
        if identity in seen or isinstance(item, excluded):
            continue
        seen.add(identity)
        kind = type(item)
        name = f"{kind.__module__}.{kind.__qualname__}"
        counts[name] += 1
        sizes[name] += sys.getsizeof(item)
        if name in _VALUE_TYPES:
            values.setdefault(name, set()).add(item)
        pending.extend(gc.get_referents(item))
    return {
        "objects": len(seen),
        "total_shallow_bytes": sum(sizes.values()),
        "types": [
            {
                "type": name,
                "count": counts[name],
                "shallow_bytes": size,
                "unique_values": len(values[name]) if name in values else None,
            }
            for name, size in sizes.most_common()
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source_digest = hashlib.sha256()
    package = Path(taut.__file__).resolve().parent
    for source in sorted(package.rglob("*.py")):
        source_digest.update(
            str(source.relative_to(package)).encode() + b"\0" + source.read_bytes() + b"\0"
        )
    with (
        patch("taut.check_service._analysis_workers", return_value=1),
        ResidentCheckSession(args.snapshot) as session,
    ):
        result = session.check(CheckRequest(args.snapshot))
        if result.exit_code != 0:
            raise RuntimeError("census requires a successful baseline check")
        del result
        gc.collect()
        data = census(session)
    data.update(
        python=platform.python_version(),
        engine_source_sha256=source_digest.hexdigest(),
        single_worker=True,
        limits=__doc__,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    print(f"objects={data['objects']} shallow_bytes={data['total_shallow_bytes']}", flush=True)


if __name__ == "__main__":
    main()
