"""Entity index with provenance and per-artifact extraction records."""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from database.connection import connect_database


def entities(text):
    found = {('email', v.lower()) for v in re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', text)}
    for value in re.findall(r'https?://[^\s<>"\)]+', text):
        domain = urlsplit(value).hostname
        if domain:
            found.add(('domain', domain.lower()))
            if domain.lower() in {'t.me', 'telegram.me', 'instagram.com', 'www.instagram.com', 'x.com'} and urlsplit(value).path.strip('/'):
                found.add(('social', domain.lower().removeprefix('www.') + urlsplit(value).path.rstrip('/').lower()))
    for value in re.findall(r'upi://pay\?[^\s<>]+', text):
        for address in parse_qs(urlsplit(value).query).get('pa', []):
            found.add(('payment', address.lower()))
    for value in re.findall(r'(?<!\w)\+\d[\d ()-]{8,18}\d(?!\w)', text):
        number = re.sub(r'\D', '', value)
        if 10 <= len(number) <= 15:
            found.add(('phone', '+' + number))
    return sorted(found)


class EntityIndex:
    def __init__(self, db_path=None):
        self.db_path = db_path
        with connect_database(db_path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS entity_observations (id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS entity_index_runs (investigation_id TEXT PRIMARY KEY, status TEXT NOT NULL, detail TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS entity_lookup ON entity_observations(kind,value)')
            db.execute('CREATE TABLE IF NOT EXISTS artifact_extractions (id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, source TEXT NOT NULL, digest TEXT NOT NULL, result TEXT NOT NULL)')

    def observe(self, investigation, source, text):
        with connect_database(self.db_path) as db:
            for kind, value in entities(text):
                key = hashlib.sha256(json.dumps([investigation, source, kind, value]).encode()).hexdigest()
                db.execute('INSERT OR IGNORE INTO entity_observations VALUES (?, ?, ?, ?, ?)', (key, investigation, kind, value, source))

    def save_extraction(self, investigation, source, digest, result):
        key = hashlib.sha256(json.dumps([investigation, source, digest]).encode()).hexdigest()
        with connect_database(self.db_path) as db:
            db.execute('INSERT OR IGNORE INTO artifact_extractions VALUES (?, ?, ?, ?, ?)', (key, investigation, source, digest, json.dumps(result)))

    def results(self, investigation):
        with connect_database(self.db_path) as db:
            extracted = [dict(r) for r in db.execute('SELECT * FROM artifact_extractions WHERE investigation_id=?', (investigation,)).fetchall()]
            related = [dict(r) for r in db.execute('''SELECT DISTINCT b.investigation_id, b.kind, b.value, b.source, a.source AS matching_source
                FROM entity_observations a JOIN entity_observations b ON a.kind=b.kind AND a.value=b.value
                WHERE a.investigation_id=? AND b.investigation_id<>? ORDER BY b.kind,b.value,b.investigation_id''', (investigation, investigation)).fetchall()]
        with connect_database(self.db_path) as db:
            run = db.execute('SELECT status,detail FROM entity_index_runs WHERE investigation_id=?', (investigation,)).fetchone()
            total = db.execute("SELECT COUNT(*) FROM entity_index_runs WHERE status='completed'").fetchone()[0]
        return {'index_status': dict(run) if run else {'status': 'pending', 'detail': 'Waiting for automatic indexing'}, 'indexed_investigations': total, 'extractions': [{**r, 'result': json.loads(r['result'])} for r in extracted], 'connections': related}


def enrich(source, investigation):
    from config import EVIDENCE_DIR
    from services.case_ocr import extract_document
    index = EntityIndex(source.db_path)
    for record in source.get_sources(investigation):
        index.observe(investigation, record.get('source_url', ''), ' '.join(str(record.get(k) or '') for k in ['source_url', 'snippet', 'title']))
    for method in [source.get_evidence, source.get_social_findings, source.get_documents]:
        for record in method(investigation):
            index.observe(investigation, record.get('source_url') or record.get('post_url') or '', ' '.join(str(record.get(k) or '') for k in ['evidence_text', 'context_text', 'post_text', 'search_snippet', 'evidence_context']))
    artifacts = [(e.get('screenshot_path'), e.get('source_url', '')) for e in source.get_evidence(investigation)]
    artifacts += [(d.get('local_path'), d.get('source_url', '')) for d in source.get_documents(investigation)]
    for finding in source.get_social_findings(investigation):
        artifacts.extend((p, finding.get('post_url', '')) for p in finding.get('screenshot_paths', []))
    for document in source.get_documents(investigation):
        if document.get('local_path') and Path(document['local_path']).is_file():
            continue
        raw = source.get_document_content(investigation, document['id'])
        if raw and len(raw) <= 20_000_000:
            digest = hashlib.sha256(raw).hexdigest()
            url = document.get('source_url', '')
            try:
                result = extract_document(raw)
                result['status'] = 'completed'
                index.observe(investigation, url, result.get('text', ''))
                for page in result.get('pages', []):
                    index.observe(investigation, url, page.get('qr_contents', ''))
            except Exception as exc:
                result = {'status': 'failed', 'error': str(exc)}
            index.save_extraction(investigation, url, digest, result)
    for filename, url in artifacts:
        if not filename:
            continue
        path = Path(filename).resolve()
        if not path.is_relative_to(EVIDENCE_DIR.resolve()) or not path.is_file():
            index.save_extraction(investigation, url, '', {'status': 'unavailable'})
            continue
        if path.stat().st_size > 20_000_000:
            index.save_extraction(investigation, url, '', {'status': 'size_limit'})
            continue
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        try:
            with connect_database(source.db_path) as db:
                cached = db.execute('SELECT result FROM artifact_extractions WHERE digest=?', (digest,)).fetchall()
            result = next((json.loads(r[0]) for r in cached if json.loads(r[0]).get('status') == 'completed'), None)
            if result is None:
                result = extract_document(raw)
            result['status'] = 'completed'
            index.observe(investigation, url, result['text'])
            for page in result['pages']:
                index.observe(investigation, url, page.get('qr_contents', ''))
        except Exception as exc:
            result = {'status': 'failed', 'error': str(exc)}
        index.save_extraction(investigation, url, digest, result)
