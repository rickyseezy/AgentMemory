"""Container entry points for Core serving, migration, and health checks."""

from __future__ import annotations

import asyncio
import json
import sys

import httpx
import uvicorn
from alembic import command
from alembic.config import Config
from neo4j import AsyncGraphDatabase

from agentmemory.operations.adapters.inbound.http_api import export_openapi_schema
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_file,
    require_private_directory,
    zero_secret,
)
from agentmemory.operations.bootstrap import create_core_app
from agentmemory.operations.infrastructure.configuration import CoreSettings
from agentmemory.operations.infrastructure.neo4j_migrations import migrate_neo4j

_HEALTHY_STATUS = 200


def serve() -> None:
    """Bind the container interface; Compose owns host-loopback publication and isolation."""
    settings = CoreSettings.from_environment()
    uvicorn.run(
        create_core_app(settings),
        host=settings.listen_host,
        port=settings.port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=30,
    )


def migrate() -> None:
    """Apply relational then Neo4j migrations while Core is exclusively stopped."""
    settings = CoreSettings.from_environment()
    _migrate_relational(settings)
    asyncio.run(_migrate_graph(settings))


def healthcheck() -> None:
    """Prove only Core startup/liveness; the later eleven-probe gate proves Ready."""
    settings = CoreSettings.from_environment()
    with httpx.Client(timeout=3, follow_redirects=False, trust_env=False) as client:
        response = client.get(
            f"http://127.0.0.1:{settings.port}/health/live",
            headers={"Host": f"127.0.0.1:{settings.port}"},
        )
    if response.status_code != _HEALTHY_STATUS:
        raise SystemExit(1)


def export_openapi() -> None:
    """Write deterministic canonical OpenAPI JSON for launcher client generation."""
    payload = json.dumps(
        export_openapi_schema(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    sys.stdout.write(f"{payload}\n")


def _migrate_relational(settings: CoreSettings) -> None:
    configuration_path = settings.relational_migrations_directory / "alembic.ini"
    if not configuration_path.is_file():
        msg = "signed relational migration bundle is unavailable"
        raise RuntimeError(msg)
    require_private_directory(settings.state_directory)
    configuration = Config(str(configuration_path))
    configuration.set_main_option("script_location", str(settings.relational_migrations_directory))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{settings.database_path}")
    command.upgrade(configuration, "head")


async def _migrate_graph(settings: CoreSettings) -> None:
    password = read_protected_file(settings.neo4j_password_file, frozenset({32}))
    try:
        # The official Neo4j 6.2 stub leaves the driver's **config untyped.
        driver = AsyncGraphDatabase.driver(  # pyright: ignore[reportUnknownMemberType]
            settings.neo4j_uri,
            auth=(settings.neo4j_username, password.hex()),
            max_connection_pool_size=4,
            connection_timeout=5,
        )
    finally:
        zero_secret(password)
    try:
        await migrate_neo4j(
            driver,
            settings.neo4j_database,
            settings.neo4j_migrations_directory,
        )
    finally:
        await driver.close()
