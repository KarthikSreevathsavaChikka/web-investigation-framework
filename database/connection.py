"""Database connections for PostgreSQL deployments and isolated SQLite tests."""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any


def configured_database_url() -> str | None:
    return os.getenv("DATABASE_URL", "").strip() or None


def is_postgresql_enabled() -> bool:
    url = configured_database_url()
    return bool(url and url.startswith(("postgresql://", "postgres://")))


def is_postgresql_connection(connection) -> bool:
    return isinstance(connection, PostgresConnection)


class PostgresRow(Mapping[str, Any]):
    """Mapping row that also supports SQLite-style numeric indexing."""

    def __init__(self, columns: list[str], values: tuple[Any, ...]):
        self._columns = columns
        self._values = values
        self._mapping = dict(zip(columns, values))

    def __getitem__(self, key: str | int) -> Any:
        return self._values[key] if isinstance(key, int) else self._mapping[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._columns)

    def __len__(self) -> int:
        return len(self._columns)


class PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self.lastrowid: int | None = None

    @staticmethod
    def _translate(sql: str) -> str:
        sql = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "BIGSERIAL PRIMARY KEY", sql, flags=re.I)
        sql = re.sub(r"BOOLEAN\s+DEFAULT\s+0", "BOOLEAN DEFAULT FALSE", sql, flags=re.I)
        sql = re.sub(r"BOOLEAN\s+DEFAULT\s+1", "BOOLEAN DEFAULT TRUE", sql, flags=re.I)
        sql = sql.replace("?", "%s")
        ignore = bool(re.search(r"INSERT\s+OR\s+IGNORE", sql, re.I))
        replace = bool(re.search(r"INSERT\s+OR\s+REPLACE", sql, re.I))
        sql = re.sub(r"INSERT\s+OR\s+(?:IGNORE|REPLACE)", "INSERT", sql, flags=re.I)
        if ignore:
            sql = f"{sql.rstrip().rstrip(';')} ON CONFLICT DO NOTHING"
        elif replace:
            match = re.search(r"INSERT\s+INTO\s+[^()]+\(([^)]+)\)", sql, re.I | re.S)
            if match:
                columns = [item.strip() for item in match.group(1).split(",")]
                updates = ", ".join(f"{item} = EXCLUDED.{item}" for item in columns)
                sql = f"{sql.rstrip().rstrip(';')} ON CONFLICT DO UPDATE SET {updates}"
        return sql

    def execute(self, sql: str, parameters=()):
        translated = self._translate(sql)
        insert = re.match(r"\s*INSERT\s+INTO\s+([a-zA-Z_][\w]*)", translated, re.I)
        serial_columns = {
            "pages": "page_id", "screenshots": "screenshot_id",
            "keyword_findings": "keyword_id", "payment_findings": "finding_id",
            "navigation_graph": "id", "crawl_logs": "log_id",
            "osint_evidence_matches": "id",
        }
        if insert and insert.group(1) in serial_columns and " RETURNING " not in translated.upper():
            translated = f"{translated.rstrip().rstrip(';')} RETURNING {serial_columns[insert.group(1)]}"
        self._cursor.execute(translated, parameters)
        if insert and self._cursor.description and insert.group(1) in serial_columns:
            row = self._cursor.fetchone()
            self.lastrowid = row[0] if row else None
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return self._row(row)

    def fetchall(self):
        return [self._row(row) for row in self._cursor.fetchall()]

    def _row(self, row):
        if row is None:
            return None
        columns = [item.name for item in self._cursor.description]
        return PostgresRow(columns, tuple(row))


class PostgresConnection:
    def __init__(self, url: str):
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("PostgreSQL support requires psycopg. Install requirements.txt.") from exc
        self._connection = psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://", 1))

    def cursor(self) -> PostgresCursor:
        return PostgresCursor(self._connection.cursor())

    def execute(self, sql: str, parameters=()) -> PostgresCursor:
        return self.cursor().execute(sql, parameters)

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.commit() if exc_type is None else self.rollback()
        self.close()


def connect_database(db_path: Path | str | None = None):
    """Use DATABASE_URL unless the caller explicitly requests a SQLite file."""
    if db_path is None and configured_database_url():
        return PostgresConnection(configured_database_url() or "")
    from config import DB_PATH

    connection = sqlite3.connect(str(db_path or DB_PATH))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
