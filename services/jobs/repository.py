from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from database.connection import connect_database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JobRepository:
    """Persistent job state shared by the API and workers."""

    def __init__(self) -> None:
        self.init_db()

    def init_db(self) -> None:
        with connect_database() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS investigation_jobs (
                    id TEXT PRIMARY KEY,
                    component TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                )"""
            )

    def create(self, component: str, target: str, payload: dict[str, Any]) -> dict[str, Any]:
        job_id = f"JOB_{uuid.uuid4().hex[:12].upper()}"
        created_at = _now()
        with connect_database() as connection:
            connection.execute(
                """INSERT INTO investigation_jobs
                (id, component, target, status, payload_json, created_at)
                VALUES (?, ?, ?, 'QUEUED', ?, ?)""",
                (job_id, component, target, json.dumps(payload), created_at),
            )
        return self.get(job_id) or {}

    def get(self, job_id: str) -> dict[str, Any] | None:
        with connect_database() as connection:
            row = connection.execute(
                "SELECT * FROM investigation_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._deserialize(dict(row)) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with connect_database() as connection:
            rows = connection.execute(
                "SELECT * FROM investigation_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._deserialize(dict(row)) for row in rows]

    def mark_running(self, job_id: str) -> dict[str, Any] | None:
        with connect_database() as connection:
            connection.execute(
                """UPDATE investigation_jobs
                SET status = 'RUNNING', started_at = ?, attempts = attempts + 1, error = NULL
                WHERE id = ?""",
                (_now(), job_id),
            )
        return self.get(job_id)

    def mark_completed(self, job_id: str, result: dict[str, Any]) -> None:
        with connect_database() as connection:
            connection.execute(
                """UPDATE investigation_jobs
                SET status = 'COMPLETED', result_json = ?, completed_at = ?
                WHERE id = ?""",
                (json.dumps(result), _now(), job_id),
            )

    def mark_failed(self, job_id: str, error: str) -> None:
        with connect_database() as connection:
            connection.execute(
                """UPDATE investigation_jobs
                SET status = 'FAILED', error = ?, completed_at = ?
                WHERE id = ?""",
                (error[:4000], _now(), job_id),
            )

    def mark_cancelling(self, job_id: str) -> None:
        with connect_database() as connection:
            connection.execute(
                "UPDATE investigation_jobs SET status = 'CANCELLING' WHERE id = ?",
                (job_id,),
            )

    def mark_cancelled(self, job_id: str) -> None:
        with connect_database() as connection:
            connection.execute(
                """UPDATE investigation_jobs
                SET status = 'CANCELLED', completed_at = ?, error = NULL
                WHERE id = ?""",
                (_now(), job_id),
            )

    @staticmethod
    def _deserialize(row: dict[str, Any]) -> dict[str, Any]:
        row["payload"] = json.loads(row.pop("payload_json") or "{}")
        row["result"] = json.loads(row.pop("result_json") or "{}")
        return row
