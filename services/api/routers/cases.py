"""Case workspace endpoints shared by the React client."""
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from services.casework import CaseRepository
from services.evidence.package import build_package, verify_package
from osint.http import get_public_url
from osint.storage import OSINTRepository

router = APIRouter(prefix='/api/v1/cases', tags=['cases'])

def repository():
    return CaseRepository()

def require_case(repo, key):
    case = next((c for c in repo.list() if c['id'] == key), None)
    if not case:
        raise HTTPException(404, 'Case not found')
    return case

class NewCase(BaseModel):
    reference: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=500)
    assignee: str = Field(default='', max_length=200)

class Activity(BaseModel):
    kind: Literal['note', 'investigation', 'review']
    text: str = Field(default='', max_length=20000)
    investigation_id: str = ''
    evidence_id: str = ''
    reviewer: str = ''
    decision: Literal['Accepted', 'Rejected', 'Needs review'] = 'Needs review'

class Website(BaseModel):
    url: str = Field(max_length=2048)

@router.get('')
def cases(repo=Depends(repository)):
    return repo.list()

@router.post('', status_code=201)
def create(body: NewCase, repo=Depends(repository)):
    if any(c['reference'] == body.reference.strip() for c in repo.list()):
        raise HTTPException(409, 'Reference already exists')
    try:
        return {'id': repo.create(body.reference, body.title, body.assignee)}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

@router.get('/{key}')
def detail(key: str, repo=Depends(repository)):
    return {'case': require_case(repo, key), 'activity': repo.activity(key)}

@router.post('/{key}/activity')
def activity(key: str, body: Activity, repo=Depends(repository)):
    require_case(repo, key)
    if body.kind in {'investigation', 'review'}:
        source = OSINTRepository()
        if not source.get_investigation(body.investigation_id):
            raise HTTPException(404, 'Investigation not found')
        if body.kind == 'review':
            if not body.reviewer.strip():
                raise HTTPException(422, 'Reviewer required')
            if not any(str(e['id']) == body.evidence_id for e in source.get_evidence(body.investigation_id)):
                raise HTTPException(404, 'Evidence not found')
    if body.kind == 'note' and not body.text.strip():
        raise HTTPException(422, 'Note required')
    repo.append(key, body.kind, body.model_dump(exclude={'kind'}))
    return {'saved': True}

@router.post('/{key}/check')
def check(key: str, body: Website, repo=Depends(repository)):
    require_case(repo, key)
    try:
        with get_public_url(body.url, timeout=15, max_bytes=5_000_000) as response:
            snapshot = {'url': body.url, 'final_url': response.url, 'status': response.status_code, 'sha256': hashlib.sha256(response.content).hexdigest()}
        previous = [a['payload'] for a in repo.activity(key) if a['kind'] == 'website_check' and a['payload']['url'] == body.url]
        snapshot['changed'] = any(snapshot[k] != previous[-1].get(k) for k in snapshot) if previous else None
        repo.append(key, 'website_check', snapshot)
        return snapshot
    except Exception as exc:
        repo.append(key, 'website_error', {'url': body.url, 'error': str(exc)})
        raise HTTPException(422, str(exc)) from exc

async def bounded_body(request, limit=20_000_000):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > limit:
            raise HTTPException(413, 'Upload exceeds size limit')
    return bytes(data)

@router.post('/{key}/extract')
async def extract(key: str, request: Request, repo=Depends(repository)):
    require_case(repo, key)
    raw = await bounded_body(request)
    try:
        from services.case_ocr import extract_document
        result = extract_document(raw)
        result['source_sha256'] = hashlib.sha256(raw).hexdigest()
        repo.append(key, 'extraction', result)
        return result
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc

@router.get('/{key}/package')
def package(key: str, repo=Depends(repository)):
    case = require_case(repo, key)
    from services.case_exports import export_case
    try:
        data = export_case(case, repo.activity(key), OSINTRepository())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return Response(data, media_type='application/zip', headers={'Content-Disposition': 'attachment; filename="case-record.zip"'})

@router.post('/{key}/verify')
async def verify(key: str, request: Request, repo=Depends(repository)):
    require_case(repo, key)
    data = await bounded_body(request)
    try:
        return verify_package(data)
    except Exception as exc:
        raise HTTPException(422, f'Invalid evidence package: {exc}') from exc

class Workflow(BaseModel):
    status: Literal['Draft', 'Under review', 'Changes requested', 'Approved']
    reviewer: str = Field(min_length=1, max_length=200)
    note: str = Field(default='', max_length=20000)

@router.post('/{key}/workflow')
def workflow(key: str, body: Workflow, repo=Depends(repository)):
    require_case(repo, key)
    history = [a for a in repo.activity(key) if a['kind'] == 'workflow']
    current = history[-1]['payload']['status'] if history else 'Draft'
    allowed = {'Draft': ['Under review'], 'Under review': ['Changes requested', 'Approved'], 'Changes requested': ['Under review'], 'Approved': ['Draft']}
    if body.status not in allowed[current] or not body.reviewer.strip():
        raise HTTPException(422, 'Invalid workflow transition or reviewer')
    payload = {**body.model_dump(), 'version': len(history) + 1}
    payload['snapshot'] = {'case': require_case(repo, key), 'activity': [a for a in repo.activity(key) if a['kind'] != 'workflow']}
    source = OSINTRepository()
    from osint.report import OSINTReportBuilder
    ids = {a['payload']['investigation_id'] for a in repo.activity(key) if a['kind'] == 'investigation'}
    payload['reports'] = {i: OSINTReportBuilder(source).build_html(i) for i in ids}
    repo.append(key, 'workflow', payload)
    return payload

@router.get('/{key}/graph')
def graph(key: str, repo=Depends(repository)):
    from services.case_analysis import entity_graph
    require_case(repo, key)
    ids = sorted({a['payload']['investigation_id'] for a in repo.activity(key) if a['kind'] == 'investigation'})
    source = OSINTRepository()
    return entity_graph([(i, source.get_sources(i)) for i in ids])

@router.get('/{key}/compare')
def compare(key: str, before: str, after: str, repo=Depends(repository)):
    from services.case_analysis import compare_records
    require_case(repo, key)
    ids = {a['payload']['investigation_id'] for a in repo.activity(key) if a['kind'] == 'investigation'}
    if before not in ids or after not in ids:
        raise HTTPException(422, 'Select two linked investigations')
    source = OSINTRepository()
    return {'domains': compare_records(source.get_candidates(before), source.get_candidates(after)), 'sources': compare_records(source.get_sources(before), source.get_sources(after)), 'indicators': compare_records(source.get_risk_indicators(before), source.get_risk_indicators(after))}

class Schedule(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    interval_hours: int = Field(default=24, ge=1, le=2160)
    enabled: bool = True

@router.post('/{key}/schedule')
def schedule(key: str, body: Schedule, repo=Depends(repository)):
    from urllib.parse import urlsplit
    require_case(repo, key)
    if urlsplit(body.url).scheme not in {'http', 'https'}:
        raise HTTPException(422, 'HTTP(S) URL required')
    repo.append(key, 'schedule', body.model_dump())
    return {'saved': True}

@router.get('/{key}/versions/{version}')
def version_download(key: str, version: int, repo=Depends(repository)):
    require_case(repo, key)
    record = next((a['payload'] for a in repo.activity(key) if a['kind'] == 'workflow' and a['payload']['version'] == version), None)
    if not record:
        raise HTTPException(404, 'Version not found')
    files = {'snapshot.json': json.dumps(record, indent=2).encode()}
    for index, html in enumerate(record.get('reports', {}).values()):
        files[f'reports/{index + 1}.html'] = html.encode()
    return Response(build_package(files), media_type='application/zip', headers={'Content-Disposition': f'attachment; filename="version-{version}.zip"'})
