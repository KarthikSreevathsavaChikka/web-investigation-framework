from __future__ import annotations

import json
import secrets

from database.connection import connect_database
from database.migrations import lock_schema_migration, record_schema_version


class VirusTotalRepository:
    def __init__(self, db_path=None):
        self.db_path = str(db_path) if db_path is not None else None
        self.init_schema()

    def connection(self):
        return connect_database(self.db_path)

    def init_schema(self) -> None:
        with self.connection() as connection:
            lock_schema_migration(connection)
            connection.execute("""CREATE TABLE IF NOT EXISTS virustotal_reports (
                id TEXT PRIMARY KEY, target TEXT NOT NULL, target_type TEXT NOT NULL,
                object_id TEXT NOT NULL, permalink TEXT NOT NULL, retrieved_at TEXT NOT NULL,
                report_json TEXT NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS virustotal_batches (
                id TEXT PRIMARY KEY, brand TEXT, domains_json TEXT NOT NULL,
                retrieved_at TEXT NOT NULL, results_json TEXT NOT NULL)""")
            record_schema_version(connection, "virustotal", 1)

    def save(self, report: dict) -> str:
        report_id = f"VT_{secrets.token_hex(5).upper()}"
        with self.connection() as connection:
            connection.execute("""INSERT INTO virustotal_reports
                (id, target, target_type, object_id, permalink, retrieved_at, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""", (
                report_id, report["target"], report["target_type"], report["object_id"],
                report["permalink"], report["retrieved_at"], json.dumps(report),
            ))
        return report_id

    def get(self, report_id: str) -> dict | None:
        with self.connection() as connection:
            row = connection.execute("SELECT id, report_json FROM virustotal_reports WHERE id = ?", (report_id,)).fetchone()
        if not row:
            return None
        report = json.loads(row["report_json"])
        report["id"] = row["id"]
        return report

    def list(self, limit: int = 50) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute("""SELECT id, target, target_type, retrieved_at
                FROM virustotal_reports ORDER BY retrieved_at DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def save_batch(self, brand: str, domains: list[str], results: list[dict]) -> str:
        from core.time_utils import now_ist

        batch_id = f"VTB_{secrets.token_hex(5).upper()}"
        retrieved_at = now_ist().isoformat(timespec="seconds")
        with self.connection() as connection:
            connection.execute("""INSERT INTO virustotal_batches
                (id, brand, domains_json, retrieved_at, results_json)
                VALUES (?, ?, ?, ?, ?)""", (
                batch_id, brand, json.dumps(domains), retrieved_at, json.dumps(results),
            ))
        return batch_id

    def get_batch(self, batch_id: str) -> dict | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM virustotal_batches WHERE id = ?", (batch_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["domains"] = json.loads(item.pop("domains_json") or "[]")
        item["results"] = json.loads(item.pop("results_json") or "[]")
        return item

    def list_batches(self, limit: int = 50) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute("""SELECT id, brand, domains_json, retrieved_at
                FROM virustotal_batches ORDER BY retrieved_at DESC LIMIT ?""", (limit,)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["domain_count"] = len(json.loads(item.pop("domains_json") or "[]"))
            items.append(item)
        return items
