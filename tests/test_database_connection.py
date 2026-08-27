import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database.connection import PostgresCursor, connect_database, is_postgresql_enabled


class _Cursor:
    description = None

    def execute(self, sql, parameters):
        self.executed = (sql, parameters)


class DatabaseConnectionTests(unittest.TestCase):
    def test_explicit_path_keeps_sqlite_for_isolated_tests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"DATABASE_URL": "postgresql://ignored"}):
                with connect_database(Path(temp_dir) / "test.db") as connection:
                    connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)")
                    connection.execute("INSERT INTO sample VALUES (?, ?)", (1, "ok"))
                    self.assertEqual(connection.execute("SELECT value FROM sample").fetchone()[0], "ok")

    def test_postgresql_configuration_detection(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://user:pass@db/app"}):
            self.assertTrue(is_postgresql_enabled())

    def test_translates_sqlite_insert_and_placeholders(self):
        raw = _Cursor()
        PostgresCursor(raw).execute(
            "INSERT OR IGNORE INTO sample (id, value) VALUES (?, ?)", (1, "ok")
        )
        sql, parameters = raw.executed
        self.assertIn("VALUES (%s, %s)", sql)
        self.assertIn("ON CONFLICT DO NOTHING", sql)
        self.assertEqual(parameters, (1, "ok"))

    def test_translates_autoincrement_definition(self):
        translated = PostgresCursor._translate("id INTEGER PRIMARY KEY AUTOINCREMENT")
        self.assertEqual(translated, "id BIGSERIAL PRIMARY KEY")

    def test_replace_names_postgresql_conflict_key(self):
        translated = PostgresCursor._translate(
            "INSERT OR REPLACE INTO osint_search_cache "
            "(cache_key, provider, payload_json, created_at) VALUES (?, ?, ?, ?)"
        )
        self.assertIn("ON CONFLICT (cache_key) DO UPDATE SET", translated)

    def test_replace_uses_composite_conflict_key(self):
        translated = PostgresCursor._translate(
            "INSERT OR REPLACE INTO osint_query_executions "
            "(investigation_id, query_id, provider) VALUES (?, ?, ?)"
        )
        self.assertIn(
            "ON CONFLICT (investigation_id, query_id, provider) DO UPDATE SET",
            translated,
        )


if __name__ == "__main__":
    unittest.main()
