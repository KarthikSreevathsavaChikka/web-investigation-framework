"""Automatically backfill historical and newly completed investigations."""
import logging
import time
from database.connection import connect_database
from osint.storage import OSINTRepository
from services.entity_index import EntityIndex, enrich


def index_pending(source):
    EntityIndex(source.db_path)
    for record in source.list_investigations():
        if record['status'] not in {'COMPLETED', 'PARTIAL'} or not record.get('completed_at'):
            continue
        key = record['id']
        with connect_database(source.db_path) as db:
            old = db.execute('SELECT status FROM entity_index_runs WHERE investigation_id=?', (key,)).fetchone()
            if old and old[0] == 'completed':
                continue
            db.execute('INSERT OR IGNORE INTO entity_index_runs VALUES (?, ?, ?)', (key, 'running', 'Extracting stored evidence'))
            db.execute('UPDATE entity_index_runs SET status=?, detail=? WHERE investigation_id=?', ('running', 'Extracting stored evidence', key))
        try:
            enrich(source, key)
            status, detail = 'completed', 'Available evidence indexed; inspect individual extraction outcomes for gaps'
        except Exception as exc:
            status, detail = 'failed', str(exc)
            logging.exception('Entity indexing failed for %s', key)
        with connect_database(source.db_path) as db:
            db.execute('UPDATE entity_index_runs SET status=?, detail=? WHERE investigation_id=?', (status, detail, key))


if __name__ == '__main__':
    while True:
        try:
            index_pending(OSINTRepository())
        except Exception:
            logging.exception('Entity indexing cycle failed')
        time.sleep(30)
