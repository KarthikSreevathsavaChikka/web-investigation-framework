"""Durable case records and append-only investigator activity."""
import json
from uuid import uuid4
from datetime import datetime, timezone
from database.connection import connect_database


class CaseRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path
        with connect_database(db_path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS investigation_cases (id TEXT PRIMARY KEY, reference TEXT UNIQUE NOT NULL, title TEXT NOT NULL, assignee TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS case_activity (id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigation_cases(id), kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)')

    def create(self, reference, title, assignee):
        if not reference.strip() or not title.strip():
            raise ValueError('Reference and title are required')
        key = str(uuid4())
        with connect_database(self.db_path) as db:
            db.execute('INSERT INTO investigation_cases VALUES (?, ?, ?, ?)', (key, reference.strip(), title.strip(), assignee.strip()))
        return key

    def list(self):
        with connect_database(self.db_path) as db:
            return [dict(r) for r in db.execute('SELECT * FROM investigation_cases ORDER BY reference').fetchall()]

    def append(self, case_id, kind, payload):
        with connect_database(self.db_path) as db:
            db.execute('INSERT INTO case_activity VALUES (?, ?, ?, ?, ?)', (str(uuid4()), case_id, kind, datetime.now(timezone.utc).isoformat(), json.dumps(payload)))

    def activity(self, case_id):
        with connect_database(self.db_path) as db:
            rows = db.execute('SELECT * FROM case_activity WHERE case_id=? ORDER BY created_at, id', (case_id,)).fetchall()
        return [{**dict(r), 'payload': json.loads(r['payload'])} for r in rows]
