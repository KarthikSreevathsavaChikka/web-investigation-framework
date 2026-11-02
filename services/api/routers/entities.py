"""Read-only demo and indexed investigation enrichment."""
import tempfile
from pathlib import Path
from fastapi import APIRouter
from services.entity_index import EntityIndex

router = APIRouter(prefix='/api/v1/entities', tags=['entities'])

@router.get('/demo')
async def demo():
    # Synthetic records never enter the operational database.
    with tempfile.TemporaryDirectory() as folder:
        index = EntityIndex(Path(folder) / 'demo.db')
        index.observe('DEMO-A', 'https://alpha.example/contact', 'Contact support@shared.example upi://pay?pa=demo@upi')
        index.observe('DEMO-B', 'https://beta.example/contact', 'Contact support@shared.example upi://pay?pa=demo@upi')
        index.observe('DEMO-C', 'https://unrelated.example', 'hello@unrelated.example')
        index.save_extraction('DEMO-A', 'https://alpha.example/contact', 'synthetic', {'status': 'fixture', 'text': 'Contact support@shared.example', 'pages': [{'page': 1, 'qr_contents': 'upi://pay?pa=demo@upi'}]})
        return index.results('DEMO-A')

@router.get('/investigations')
def investigations():
    from osint.storage import OSINTRepository
    return [{'id': r['id'], 'target': r.get('target_url') or r.get('target_domain'), 'status': r['status']} for r in OSINTRepository().list_investigations() if r.get('completed_at')]

@router.get('/{investigation_id}')
def results(investigation_id: str):
    from osint.storage import OSINTRepository
    from fastapi import HTTPException
    source = OSINTRepository()
    if not source.get_investigation(investigation_id):
        raise HTTPException(404, 'Investigation not found')
    result = EntityIndex().results(investigation_id)
    records = {r['id']: r for r in source.list_investigations() if r.get('completed_at')}
    result['total_investigations'] = len(records)
    result['connections'] = [{**c, 'target': records[c['investigation_id']].get('target_domain'),
        'strength': 'Weak: shared source domain' if c['kind'] == 'domain' else 'Exact identifier match; review context'}
        for c in result['connections'] if c['investigation_id'] in records]
    return result
