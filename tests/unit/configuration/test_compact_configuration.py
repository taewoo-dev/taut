from pathlib import Path

import pytest
from tests.utils.config import assurance_toml

from taut.configuration.path_patterns import compact_patterns
from taut.loading.config_loader import load_project_configuration
from taut.loading.errors import PolicyConfigError


def config_text(extra: str = "") -> str:
    return (
        '[tool.taut]\n[tool.taut.roles]\nservice=["app/*.py"]\n'
        'dto=["contracts/*.py"]\n[tool.taut.allow]\n'
        'service=["service", "dto"]\ndto=["dto"]\n' + assurance_toml(pyproject=True) + "\n" + extra
    )


def test_groups_and_grouped_effects_preserve_policy(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    explicit = config_text(
        '[[tool.taut.effects]]\nsymbol="app.clock.now"\neffects=["time.now"]\n'
        'access="approved_wrapper"\n[[tool.taut.effects]]\nsymbol="app.clock.today"\n'
        'effects=["time.now"]\naccess="approved_wrapper"\n'
    )
    path.write_text(explicit)
    before = load_project_configuration(tmp_path)
    compact = config_text(
        '[tool.taut.role_groups]\ncontracts=["dto"]\n[[tool.taut.effects]]\n'
        'symbols=["app.clock.now", "app.clock.today"]\neffects=["time.now"]\n'
        'access="approved_wrapper"\n'
    ).replace('service=["service", "dto"]', 'service=["service", "@contracts"]')
    path.write_text(compact)
    assert load_project_configuration(tmp_path).digest() == before.digest()


@pytest.mark.parametrize(
    "extra, replacement",
    [
        ('[tool.taut.role_groups]\nx=["@x"]', "@x"),
        ('[tool.taut.role_groups]\nx=["typo"]', "@x"),
        ("[tool.taut.role_groups]\nx=[]", "@x"),
        ('[tool.taut.role_groups]\nx=["dto"]', "@missing"),
        ('[[tool.taut.effects]]\nsymbol="app.x"\nsymbols=["app.y"]\neffects=["time.now"]', "dto"),
        ('[[tool.taut.effects]]\nsymbols=[]\neffects=["time.now"]', "dto"),
    ],
)
def test_invalid_compact_declarations_fail(tmp_path: Path, extra: str, replacement: str) -> None:
    (tmp_path / "pyproject.toml").write_text(
        config_text(extra).replace(
            'service=["service", "dto"]', f'service=["service", "{replacement}"]'
        )
    )
    with pytest.raises(PolicyConfigError):
        load_project_configuration(tmp_path)


def test_compaction_does_not_confuse_a_literal_filename_with_a_wildcard() -> None:
    patterns = ("app/foo.py", "app/**/foo.py", "app/*.py", "app/**/*.py")
    assert compact_patterns(patterns) == patterns[:-1]


def test_group_cannot_override_builtin_effect(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        config_text(
            '[[tool.taut.effects]]\nsymbols=["datetime.datetime.now", "app.clock"]\n'
            'effects=["external.call"]\n'
        )
    )
    with pytest.raises(PolicyConfigError):
        load_project_configuration(tmp_path)
