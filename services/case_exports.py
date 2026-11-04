"""Build case exports from persisted sources with confined artifact reads."""
import hashlib
import json
from pathlib import Path
from config import EVIDENCE_DIR
from osint.report import OSINTReportBuilder
from services.evidence.package import build_package, MAX_TOTAL_BYTES


def export_case(case, activity, source):
    files = {'case.json': json.dumps({'case': case, 'activity': activity}, indent=2).encode()}
    missing = []
    root = EVIDENCE_DIR.resolve()
    for index, investigation_id in enumerate(sorted({a['payload']['investigation_id'] for a in activity if a['kind'] == 'investigation'})):
        prefix = f'investigations/{index + 1}'
        files[f'{prefix}/report.html'] = OSINTReportBuilder(source).build_html(investigation_id).encode()
        files[f'{prefix}/report.json'] = OSINTReportBuilder(source).build_json(investigation_id).encode()
        for number, evidence in enumerate(source.get_evidence(investigation_id)):
            path = Path(evidence['screenshot_path']).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                missing.append({'investigation_id': investigation_id, 'evidence_id': evidence['id'], 'reason': 'Original unavailable'})
                continue
            if path.stat().st_size + sum(map(len, files.values())) > MAX_TOTAL_BYTES:
                raise ValueError('Case exceeds the 200 MiB export limit')
            content = path.read_bytes()
            if evidence.get('sha256') and hashlib.sha256(content).hexdigest() != evidence['sha256']:
                raise ValueError(f"Original hash mismatch for evidence {evidence['id']}")
            files[f'{prefix}/originals/{number}{path.suffix}'] = content
        extras = source.get_document_viewer_captures(investigation_id)
        for finding in source.get_social_findings(investigation_id):
            extras.extend({'screenshot_path': path} for path in finding.get('screenshot_paths', []))
        for document in source.get_documents(investigation_id):
            content = source.get_document_content(investigation_id, document['id'])
            if content is not None:
                if document.get('sha256') and hashlib.sha256(content).hexdigest() != document['sha256']:
                    raise ValueError('Document hash mismatch')
                files[f"{prefix}/documents/{document['id']}"] = content
            elif document.get('local_path'):
                extras.append({'screenshot_path': document['local_path'], 'sha256': document.get('sha256')})
            else:
                missing.append({'document_id': document['id'], 'reason': 'Original unavailable'})
            for screenshot in document.get('page_screenshots', []):
                path = screenshot if isinstance(screenshot, str) else screenshot.get('screenshot_path') or screenshot.get('path')
                if path:
                    extras.append({'screenshot_path': path})
        for number, artifact in enumerate(extras):
            path = Path(artifact['screenshot_path']).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                missing.append({'investigation_id': investigation_id, 'artifact': path.name, 'reason': 'Original unavailable'})
                continue
            if path.stat().st_size + sum(map(len, files.values())) > MAX_TOTAL_BYTES:
                raise ValueError('Case exceeds the 200 MiB export limit')
            content = path.read_bytes()
            if artifact.get('sha256') and hashlib.sha256(content).hexdigest() != artifact['sha256']:
                raise ValueError('Artifact hash mismatch')
            files[f'{prefix}/additional-originals/{number}{path.suffix}'] = content
    files['export-coverage.json'] = json.dumps({'missing': missing, 'scope': 'Case records, linked reports, evidence screenshots, social screenshots, document originals and document captures'}, indent=2).encode()
    return build_package(files)
