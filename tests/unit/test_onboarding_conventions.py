from pathlib import Path

from taut.onboarding_roles import (
    answer_role_selectors,
    observe_roles,
    synthesize_role_matchers,
)


def test_reviewed_nested_conventions_use_priority_without_file_exclusions(tmp_path: Path) -> None:
    files = ("app/services/order.py", "app/services/workflows/checkout.py")
    for file in files:
        target = tmp_path / file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("VALUE = 1\n")
    selectors = answer_role_selectors(
        {
            "role_selectors": [
                {"role": "service", "include": ["app/services/*.py"], "reason": "services"},
                {
                    "role": "workflow",
                    "include": ["app/services/workflows/*.py"],
                    "priority": 10,
                    "reason": "workflow composition",
                },
            ]
        },
        files,
    )
    observations = observe_roles(tmp_path, files, {}, {}, selectors)
    assert [item.recommended for item in observations] == ["service", "workflow"]
    matchers = synthesize_role_matchers(observations, selectors)
    assert all(not item.exclude for item in matchers)
    assert next(item.priority for item in matchers if item.role == "workflow") == 10
    assert all(file not in item.include for item in matchers for file in files)


def test_mixed_directory_does_not_generate_silent_file_exemptions(tmp_path: Path) -> None:
    files = ("app/services/order.py", "app/services/schema.py")
    for file in files:
        target = tmp_path / file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("VALUE = 1\n")
    observations = observe_roles(tmp_path, files, {}, {files[1]: "schema"})
    matchers = synthesize_role_matchers(observations, ())
    service = next(item for item in matchers if item.role == "service")
    # The overlap is left visible for preflight to reject; it is not carved out.
    assert not service.exclude
    assert "app/services/*.py" in service.include


def test_filename_convention_covers_future_files(tmp_path: Path) -> None:
    target = tmp_path / "orders_service.py"
    target.write_text("VALUE = 1\n")
    matchers = synthesize_role_matchers(observe_roles(tmp_path, (target.name,), {}, {}), ())
    assert matchers[0].include == ("*_service.py", "*_service.pyi")
