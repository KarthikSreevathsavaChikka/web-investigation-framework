"""Schema-version tracking shared by application components."""

from datetime import datetime, timezone

from database.connection import is_postgresql_connection


OSINT_SCHEMA_LOCK_ID = 872_041_903


def lock_schema_migration(connection) -> None:
    """Serialize PostgreSQL DDL across API, UI, and worker processes."""
    if is_postgresql_connection(connection):
        connection.execute("SELECT pg_advisory_xact_lock(?)", (OSINT_SCHEMA_LOCK_ID,))


def schema_version_exists(connection, component: str, version: int) -> bool:
    """Check a version without issuing DDL when the migrations table is absent."""
    if is_postgresql_connection(connection):
        table_exists = connection.execute(
            """SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'schema_migrations'
            )"""
        ).fetchone()[0]
    else:
        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone() is not None
    if not table_exists:
        return False
    return connection.execute(
        "SELECT 1 FROM schema_migrations WHERE component = ? AND version = ?",
        (component, version),
    ).fetchone() is not None


def record_schema_version(connection, component: str, version: int) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
            component TEXT NOT NULL,
            version INTEGER NOT NULL,
            applied_at TEXT NOT NULL,
            PRIMARY KEY (component, version)
        )"""
    )
    connection.execute(
        """INSERT OR IGNORE INTO schema_migrations (component, version, applied_at)
        VALUES (?, ?, ?)""",
        (component, version, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
