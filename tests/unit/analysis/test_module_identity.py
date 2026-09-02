from __future__ import annotations

from pathlib import Path

from taut.analysis.module_identity import (
    absolute_import_base,
    module_identity,
    most_specific_source_root,
    resolve_internal_import,
)
from taut.domain.ids import ModuleId


def test_module_identity_primitives_share_source_and_import_semantics() -> None:
    selected = most_specific_source_root(
        Path("packages/orders/src/orders/service.py"),
        (Path("."), Path("packages/orders/src")),
    )
    assert selected == Path("packages/orders/src")

    module, is_package = module_identity(Path("orders/services/payment.py"))
    assert module == ModuleId("orders.services.payment")
    assert is_package is False
    assert absolute_import_base(module, is_package, "models", 2) == "orders.models"

    modules = {
        name: ModuleId(name) for name in ("orders", "orders.models", "orders.models.payment")
    }
    assert resolve_internal_import(
        "orders.models.payment.Payment", "orders.models.payment", modules
    ) == ModuleId("orders.models.payment")


def test_module_identity_stably_normalizes_non_importable_path_parts() -> None:
    first = module_identity(Path("admin-api/service.py"))[0]
    second = module_identity(Path("admin-api/service.py"))[0]

    assert first == second
    assert first.value.startswith("admin_api_")
