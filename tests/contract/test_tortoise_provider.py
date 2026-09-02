from typing import cast

from tests.utils.builders import analyze, make_context, make_source

from taut.analysis.contracts import ContextManagerProvider, ResolverSettings
from taut.analysis.framework.tortoise import (
    TORTOISE_CONNECTIONS,
    TORTOISE_FIELDS,
    TORTOISE_MODELS,
    TORTOISE_QUERIES,
    TORTOISE_RAW_SQL,
    TORTOISE_RELATIONSHIPS,
    TORTOISE_TRANSACTIONS,
    TortoiseModelFact,
    TortoiseProvider,
    TortoiseQueryFact,
    TortoiseRawSQLFact,
)
from taut.analysis.providers import apply_fact_providers, apply_fact_providers_incremental
from taut.domain.ids import RuleId, SymbolId
from taut.loading.policy_extensions import load_boundary_extensions
from taut.plugins.v1 import TortoiseProvider as PublicTortoiseProvider
from taut.policy.engine import PolicyEngine
from taut.policy.rules import builtin_rule_registry


def test_tortoise_provider_extracts_models_fields_relationships_and_queries() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from tortoise import fields
from tortoise.models import Model
class Base(Model):
    id = fields.IntField(pk=True)
class User(Base):
    team = fields.ForeignKeyField("models.Team", related_name="users")
""",
        ),
        make_source(
            "app/repository.py",
            """from app.models import User
async def load():
    found = await User.filter(active=True)
    created = await User.create(name="Ada")
    updated = await User.filter(active=True).update(name="Grace")
    return found, created, updated
""",
        ),
    )
    result = apply_fact_providers(snapshot, (TortoiseProvider(),))
    models = cast(tuple[TortoiseModelFact, ...], result.capabilities[TORTOISE_MODELS])
    queries = cast(tuple[TortoiseQueryFact, ...], result.capabilities[TORTOISE_QUERIES])

    assert {fact.symbol.value for fact in models} == {"app.models.Base", "app.models.User"}
    assert len(result.capabilities[TORTOISE_FIELDS]) == 2
    assert len(result.capabilities[TORTOISE_RELATIONSHIPS]) == 1
    assert {(fact.operation, fact.is_write) for fact in queries} == {
        ("create", True),
        ("filter", False),
        ("update", True),
    }


def test_tortoise_provider_extracts_transaction_connection_and_raw_sql() -> None:
    resolver = ResolverSettings(
        context_manager_providers=(
            ContextManagerProvider(
                SymbolId("tortoise.transactions.in_transaction"),
                SymbolId("tortoise.backends.base.client.TransactionalDBClient"),
            ),
        )
    )
    snapshot = analyze(
        make_source(
            "app/repository.py",
            """from tortoise.expressions import RawSQL
from tortoise.transactions import in_transaction
async def run(sql: str):
    expression = RawSQL("count(*)")
    async with in_transaction() as connection:
        await connection.execute_query("select 1")
        await connection.execute_script(sql)
        await connection.commit()
    return expression
""",
        ),
        resolver=resolver,
    )
    result = apply_fact_providers(snapshot, (TortoiseProvider(),))
    raw = cast(tuple[TortoiseRawSQLFact, ...], result.capabilities[TORTOISE_RAW_SQL])

    assert len(result.capabilities[TORTOISE_CONNECTIONS]) == 1
    assert len(result.capabilities[TORTOISE_TRANSACTIONS]) == 2
    assert {(fact.operation, fact.is_literal, fact.is_dynamic) for fact in raw} == {
        ("RawSQL", True, False),
        ("execute_query", True, False),
        ("execute_script", False, True),
    }

    context = make_context(
        result,
        roles={"query": ("app/repository.py",)},
        allowed_imports={"query": frozenset({"query"})},
        transaction_owners=frozenset({"service"}),
        boundary_policy=load_boundary_extensions({}),
    )
    policy_result = PolicyEngine(builtin_rule_registry()).run(context)
    assert RuleId("TX001") in {finding.rule_id for finding in policy_result.findings}


def test_tortoise_provider_does_not_infer_from_unrelated_method_names() -> None:
    snapshot = analyze(
        make_source(
            "app/noise.py",
            """class Model: pass
class Search:
    def filter(self): return self
    def raw(self, value): return value
search = Search()
search.filter()
search.raw("not sql")
""",
        )
    )
    result = apply_fact_providers(snapshot, (TortoiseProvider(),))
    assert result.capabilities[TORTOISE_MODELS] == ()
    assert result.capabilities[TORTOISE_QUERIES] == ()
    assert result.capabilities[TORTOISE_RAW_SQL] == ()


def test_tortoise_provider_propagates_queryset_through_first_party_return() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            "from tortoise.models import Model\nclass User(Model): pass\n",
        ),
        make_source(
            "app/repository.py",
            "from app.models import User\ndef active_users(): return User.filter(active=True)\n",
        ),
        make_source(
            "app/service.py",
            "from app.repository import active_users\n"
            "async def disable(): return await active_users().update(active=False)\n",
        ),
    )
    result = apply_fact_providers(snapshot, (TortoiseProvider(),))
    queries = cast(tuple[TortoiseQueryFact, ...], result.capabilities[TORTOISE_QUERIES])

    assert any(
        fact.operation == "update" and fact.module_id.value == "app.service" for fact in queries
    )


def test_tortoise_connection_registry_get_is_not_a_model_query() -> None:
    snapshot = analyze(
        make_source(
            "app/db.py",
            """from tortoise import connections
async def run():
    connection = connections.get('default')
    await connection.execute_query('select 1')
""",
        )
    )
    result = apply_fact_providers(snapshot, (TortoiseProvider(),))
    assert len(result.capabilities[TORTOISE_CONNECTIONS]) == 1
    assert result.capabilities[TORTOISE_QUERIES] == ()
    assert len(result.capabilities[TORTOISE_RAW_SQL]) == 1
    assert result.capabilities[TORTOISE_TRANSACTIONS] == ()


def test_tortoise_provider_incremental_result_matches_full_analysis() -> None:
    original = analyze(
        make_source(
            "app/models.py",
            "from tortoise.models import Model\nclass User(Model): pass\n",
        )
    )
    provider = TortoiseProvider()
    previous = apply_fact_providers(original, (provider,))
    changed = analyze(
        make_source(
            "app/models.py",
            "from tortoise.models import Model\nclass User(Model): pass\nclass Team(Model): pass\n",
        )
    )
    incremental = apply_fact_providers_incremental(
        changed,
        (provider,),
        previous,
        frozenset(changed.modules),
    )
    full = apply_fact_providers(changed, (provider,))
    assert incremental.capabilities == full.capabilities


def test_tortoise_provider_is_public_plugin_contract() -> None:
    provider = PublicTortoiseProvider()
    assert provider.id == "taut.tortoise"
    assert {item.id for item in provider.provides} == {
        TORTOISE_MODELS,
        TORTOISE_FIELDS,
        TORTOISE_RELATIONSHIPS,
        TORTOISE_CONNECTIONS,
        TORTOISE_TRANSACTIONS,
        TORTOISE_QUERIES,
        TORTOISE_RAW_SQL,
    }


def test_tortoise_facts_drive_layer_write_and_raw_sql_rules() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            "from tortoise.models import Model\nclass User(Model): pass\n",
        ),
        make_source(
            "app/service.py",
            "from app.models import User\nasync def run(): return await User.filter(active=True)\n",
        ),
        make_source(
            "app/query.py",
            "from app.models import User\nasync def run(): return await User.create(name='Ada')\n",
        ),
        make_source(
            "app/raw_query.py",
            "from app.models import User\nasync def run(): return await User.raw('select 1')\n",
        ),
        make_source(
            "app/adapter.py",
            "from app.models import User\nasync def run(): return await User.get(id=1)\n",
        ),
    )
    snapshot = apply_fact_providers(snapshot, (TortoiseProvider(),))
    context = make_context(
        snapshot,
        roles={
            "model": ("app/models.py",),
            "service": ("app/service.py",),
            "query": ("app/query.py",),
            "raw_query": ("app/raw_query.py",),
            "adapter": ("app/adapter.py",),
        },
        allowed_imports={
            role: frozenset({role, "model"})
            for role in ("model", "service", "query", "raw_query", "adapter")
        },
        boundary_policy=load_boundary_extensions({}),
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)
    assert {finding.rule_id for finding in result.findings}.issuperset(
        {
            RuleId("SERVICE001"),
            RuleId("QUERY001"),
            RuleId("SQL001"),
            RuleId("ADAPTER001"),
        }
    )
