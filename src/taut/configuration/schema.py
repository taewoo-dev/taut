from __future__ import annotations

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES


def configuration_schema_payload() -> dict[str, object]:
    return {
        "schema_version": 5,
        "extend": {
            "type": "path",
            "description": "Explicit base [tool.taut] file; child tables merge and arrays replace.",
        },
        "role_groups": {
            "type": "table of non-empty arrays of declared role names",
            "references": "@group in allow arrays; union only, no nesting or transitive edges",
        },
        "effects": {
            "symbols": "exactly one of symbol (string) or symbols (non-empty unique string array)",
            "policy": "effects and access apply identically to each exact symbol",
        },
        "roles": {
            "include": "stable directory or filename patterns; * crosses / (fnmatchcase)",
            "exclude": "explicit exclusions only; init does not invent per-file carve-outs",
            "priority": "highest matching role wins; tied roles fail",
            "init": "role_selectors accepts include, exclude, priority and a review reason",
        },
        "workspace": {
            "schema_version": 1,
            "members": "non-empty unique project-relative member directories",
            "analysis": "each member uses an isolated configuration and analysis graph",
        },
        "strict": {
            "type": "boolean",
            "default": True,
            "description": "Enforce findings and project assurance completeness.",
        },
        "transaction": {
            "owner_roles": "roles allowed to create or finish transactions",
            "participant_roles": "roles joining a caller-owned transaction without committing it",
            "session_providers": "fully qualified context-manager call symbols",
            "boundary_decorators": "fully qualified transaction decorator symbols",
            "boundary_contexts": "fully qualified atomic transaction context-manager symbols",
            "provider_item_types": "optional provider-symbol to yielded-type mapping",
        },
        "code_conventions": {
            "response_mapper_name": "single project-standard Response mapper method",
            "dto_base_symbols": "fully qualified immutable DTO base classes",
            "exception_code_argument_names": "accepted constructor keyword names",
            "exception_code_field_names": "accepted class field names",
            "test_http_fixture_symbols": "approved pytest fixture symbols",
        },
        "size": {
            "default_max_lines": "positive project-wide fallback",
            "role_max_lines": "positive per-role limits no larger than the fallback",
            "init_answer": "accept observed recommendation or provide explicit values",
        },
        "assurance": {
            "features": {
                "required_keys": BUILTIN_ASSURANCE_FEATURES,
                "values": ("required", "absent"),
            },
            "max_approvals": {"type": "integer", "minimum": 0, "default": 0},
            "max_inline_ignores": {"type": "integer", "minimum": 0, "default": 0},
            "assertions": {
                "fields": ("domain", "kind", "target", "state", "reason"),
                "state": "not_applicable",
            },
        },
        "exclusions": {
            "fields": ("patterns", "reason"),
            "description": "Reasoned Python source exclusions; stale patterns fail assurance.",
        },
    }
