"""Container entry-point and module execution tests."""

from __future__ import annotations

import runpy
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
import pytest
import uvicorn
from alembic import command
from neo4j import AsyncGraphDatabase

from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
from agentmemory.operations.bootstrap import create_core_app
from agentmemory.operations.infrastructure import entrypoints
from agentmemory.operations.infrastructure.configuration import CoreSettings
from tests.core.support import write_secret

if TYPE_CHECKING:
    from alembic.config import Config


def _settings(tmp_path: Path) -> CoreSettings:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return CoreSettings(
        state_directory=state,
        artifact_directory=tmp_path / "artifacts",
        api_credential_file=tmp_path / "api-credential",
        neo4j_password_file=tmp_path / "neo4j-password",
        relational_migrations_directory=tmp_path / "relational",
        neo4j_migrations_directory=tmp_path / "neo4j",
        embedding_model_revision="embedding-revision",
        reranking_model_revision="reranking-revision",
        extraction_model_revision="extraction-revision",
    )


def _inject_settings(monkeypatch: pytest.MonkeyPatch, settings: CoreSettings) -> None:
    def from_environment(cls: type[CoreSettings]) -> CoreSettings:
        del cls
        return settings

    monkeypatch.setattr(
        CoreSettings,
        "from_environment",
        classmethod(from_environment),
    )


def test_serve_uses_closed_container_network_server_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    application = object()
    observed: dict[str, object] = {}
    _inject_settings(monkeypatch, settings)

    def create_application(value: CoreSettings) -> object:
        assert value is settings
        return application

    monkeypatch.setattr(entrypoints, "create_core_app", create_application)

    def run(app: object, **options: object) -> None:
        observed["app"] = app
        observed.update(options)

    monkeypatch.setattr(uvicorn, "run", run)

    entrypoints.serve()

    assert observed == {
        "app": application,
        "host": "0.0.0.0",  # noqa: S104 -- Exact certified container-only bind.
        "port": 9411,
        "access_log": False,
        "proxy_headers": False,
        "server_header": False,
        "timeout_graceful_shutdown": 30,
    }


def test_migrate_runs_relational_before_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    calls: list[str] = []
    _inject_settings(monkeypatch, settings)

    def relational(value: CoreSettings) -> None:
        assert value is settings
        calls.append("relational")

    monkeypatch.setattr(entrypoints, "_migrate_relational", relational)

    async def graph(value: CoreSettings) -> None:
        assert value is settings
        calls.append("graph")

    monkeypatch.setattr(entrypoints, "_migrate_graph", graph)

    entrypoints.migrate()

    assert calls == ["relational", "graph"]


@pytest.mark.parametrize("status_code", [200, 503])
def test_healthcheck_proves_liveness_without_claiming_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    settings = _settings(tmp_path)
    observed: list[httpx.Request] = []
    real_client = httpx.Client
    _inject_settings(monkeypatch, settings)

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(status_code)

    def client_factory(**options: object) -> httpx.Client:
        assert options == {"timeout": 3, "follow_redirects": False, "trust_env": False}
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "Client", client_factory)

    if status_code == 200:
        entrypoints.healthcheck()
    else:
        with pytest.raises(SystemExit) as raised:
            entrypoints.healthcheck()
        assert raised.value.code == 1
    assert observed[0].url == "http://127.0.0.1:9411/health/live"
    assert "Authorization" not in observed[0].headers
    assert observed[0].headers["Host"] == "127.0.0.1:9411"


def test_relational_migration_requires_the_signed_bundle_and_private_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    with pytest.raises(RuntimeError, match="signed relational migration bundle"):
        entrypoints._migrate_relational(settings)  # pyright: ignore[reportPrivateUsage]

    settings.relational_migrations_directory.mkdir()
    (settings.relational_migrations_directory / "alembic.ini").write_text("[alembic]\n")
    observed: dict[str, object] = {}

    def upgrade(configuration: object, revision: str) -> None:
        observed["script_location"] = cast("Config", configuration).get_main_option(
            "script_location"
        )
        observed["sqlalchemy.url"] = cast("Config", configuration).get_main_option("sqlalchemy.url")
        observed["revision"] = revision

    monkeypatch.setattr(command, "upgrade", upgrade)

    entrypoints._migrate_relational(settings)  # pyright: ignore[reportPrivateUsage]

    assert observed == {
        "script_location": str(settings.relational_migrations_directory),
        "sqlalchemy.url": f"sqlite:///{settings.database_path}",
        "revision": "head",
    }


@dataclass(slots=True)
class _Driver:
    closed: bool = False

    async def close(self) -> None:
        self.closed = True


@dataclass(slots=True)
class _Store:
    engine: object = field(default_factory=object)
    observed: bool = False
    closed: bool = False
    fail_start: bool = False

    async def observe_and_enforce_policy(self) -> None:
        self.observed = True
        if self.fail_start:
            msg = "startup policy failed"
            raise RuntimeError(msg)

    async def close(self) -> None:
        self.closed = True


@dataclass(slots=True)
class _ProviderClient:
    closed: bool = False

    async def aclose(self) -> None:
        self.closed = True


def _patch_composition_resources(
    monkeypatch: pytest.MonkeyPatch,
    store: _Store,
    driver: _Driver,
    provider_client: _ProviderClient,
) -> None:
    def create_store(
        cls: type[SqliteCoreStore],
        database_path: Path,
        policy: object,
    ) -> _Store:
        del cls, database_path, policy
        return store

    def create_driver(uri: str, **options: object) -> _Driver:
        del uri, options
        return driver

    def create_provider_client(**options: object) -> _ProviderClient:
        del options
        return provider_client

    monkeypatch.setattr(SqliteCoreStore, "create", classmethod(create_store))
    monkeypatch.setattr(AsyncGraphDatabase, "driver", create_driver)
    monkeypatch.setattr(httpx, "AsyncClient", create_provider_client)


@pytest.mark.asyncio
@pytest.mark.parametrize("settings_source", ["explicit", "environment"])
async def test_core_composition_owns_and_closes_every_runtime_resource(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings_source: str,
) -> None:
    settings = _settings(tmp_path)
    write_secret(settings.neo4j_password_file, b"n" * 32)
    store = _Store()
    driver = _Driver()
    provider_client = _ProviderClient()
    _patch_composition_resources(monkeypatch, store, driver, provider_client)
    if settings_source == "environment":
        _inject_settings(monkeypatch, settings)

    application = create_core_app(None if settings_source == "environment" else settings)
    async with application.router.lifespan_context(application):
        assert store.observed

    assert store.closed
    assert driver.closed
    assert provider_client.closed


@pytest.mark.asyncio
async def test_core_composition_closes_every_resource_when_startup_policy_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    write_secret(settings.neo4j_password_file, b"n" * 32)
    store = _Store(fail_start=True)
    driver = _Driver()
    provider_client = _ProviderClient()
    _patch_composition_resources(monkeypatch, store, driver, provider_client)

    application = create_core_app(settings)
    with pytest.raises(RuntimeError, match="startup policy failed"):
        async with application.router.lifespan_context(application):
            pytest.fail("startup policy failure must prevent serving")

    assert store.closed
    assert driver.closed
    assert provider_client.closed


@pytest.mark.asyncio
async def test_graph_migration_uses_protected_secret_and_closes_driver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    password = b"p" * 32
    write_secret(settings.neo4j_password_file, password)
    driver = _Driver()
    observed: dict[str, object] = {}

    def driver_factory(uri: str, **options: object) -> _Driver:
        observed["uri"] = uri
        observed.update(options)
        return driver

    async def migrate_graph(
        selected_driver: object,
        database: str,
        directory: Path,
    ) -> None:
        assert selected_driver is driver
        observed["database"] = database
        observed["directory"] = directory

    monkeypatch.setattr(AsyncGraphDatabase, "driver", driver_factory)
    monkeypatch.setattr(entrypoints, "migrate_neo4j", migrate_graph)

    await entrypoints._migrate_graph(settings)  # pyright: ignore[reportPrivateUsage]

    assert driver.closed
    assert observed == {
        "uri": "neo4j://neo4j:7687",
        "auth": ("agentmemory", password.hex()),
        "max_connection_pool_size": 4,
        "connection_timeout": 5,
        "database": "neo4j",
        "directory": settings.neo4j_migrations_directory,
    }


def test_daemon_module_calls_serve_only_as_main(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[None] = []
    monkeypatch.setattr(entrypoints, "serve", lambda: calls.append(None))
    module = Path(__file__).parents[2] / "apps" / "daemon" / "main.py"

    runpy.run_path(str(module), run_name="agentmemory_daemon_import_test")
    assert calls == []
    runpy.run_path(str(module), run_name="__main__")
    assert calls == [None]
