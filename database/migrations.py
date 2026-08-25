"""Schema-version tracking shared by application components."""

from datetime import datetime, timezone


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
