from __future__ import annotations

from tests.utils.builders import analyze, make_source

from taut.incremental.semantic_digests import SemanticDigestIndex


def _index(source: str) -> SemanticDigestIndex:
    snapshot = analyze(make_source("app/service.py", source))
    return SemanticDigestIndex.build(snapshot.modules.values())


def test_coordinates_and_source_hash_do_not_change_semantic_digests() -> None:
    compact = _index("def run(value: int) -> int:\n    return value\n")
    shifted = _index("\n\n\ndef run(value: int) -> int:\n    return value\n")

    assert shifted == compact


def test_body_only_literal_edit_preserves_module_interface() -> None:
    before = _index("def run() -> int:\n    return 1\n")
    after = _index("def run() -> int:\n    return 2\n")

    assert after.module_interfaces == before.module_interfaces
    assert after.definitions == before.definitions


def test_signature_edit_changes_definition_and_module_interface() -> None:
    before = _index("def run(value: int) -> int:\n    return value\n")
    after = _index("def run(value: str) -> str:\n    return value\n")

    assert after.module_interfaces != before.module_interfaces
    assert after.definitions != before.definitions


def test_call_edit_changes_only_its_semantic_input_family() -> None:
    before = _index("def first(): pass\ndef second(): pass\ndef run():\n    first()\n")
    after = _index("def first(): pass\ndef second(): pass\ndef run():\n    second()\n")

    assert after.module_interfaces == before.module_interfaces
    assert after.calls != before.calls
    assert after.bindings == before.bindings


def test_digest_order_is_deterministic_across_module_input_order() -> None:
    snapshot = analyze(
        make_source("app/a.py", "def a(): pass\n"),
        make_source("app/b.py", "def b(): pass\n"),
    )
    modules = tuple(snapshot.modules.values())

    assert SemanticDigestIndex.build(modules) == SemanticDigestIndex.build(reversed(modules))
