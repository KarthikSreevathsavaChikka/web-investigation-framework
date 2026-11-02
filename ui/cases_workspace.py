import io
import json
import hashlib
import subprocess
import shutil
import tempfile
from pathlib import Path
import streamlit as st
from services.casework import CaseRepository
from services.evidence.package import build_package, verify_package
from osint.storage import OSINTRepository
from osint.http import get_public_url


def render_cases_workspace():
    st.title('Cases and evidence')
    repo = CaseRepository()
    with st.expander('Create case'):
        with st.form('new_case'):
            reference = st.text_input('Reference number')
            title = st.text_input('Case title')
            assignee = st.text_input('Assigned investigator')
            if st.form_submit_button('Create case'):
                try:
                    repo.create(reference, title, assignee)
                    st.success('Case created')
                except Exception as exc:
                    st.error(str(exc))
    cases = repo.list()
    if not cases:
        st.info('Create a case to begin.')
        return
    case = st.selectbox('Case', cases, format_func=lambda c: f"{c['reference']} — {c['title']}")
    key = case['id']
    history = repo.activity(key)
    overview, review, monitor, extraction, packages = st.tabs(['Case record', 'Evidence review', 'Website checks', 'OCR and QR', 'Evidence packages'])
    with overview:
        st.write('Assigned investigator:', case['assignee'])
        investigations = OSINTRepository().list_investigations()
        if investigations:
            selected = st.selectbox('Investigation', investigations, format_func=lambda i: f"{i['id']} — {i.get('target_domain', '')}")
            if st.button('Link investigation'):
                repo.append(key, 'investigation', {'investigation_id': selected['id']})
                st.success('Investigation linked')
        note = st.text_area('Case note')
        if st.button('Save note') and note.strip():
            repo.append(key, 'note', {'text': note})
            st.success('Note saved')
        st.json(history)
    with review:
        linked = sorted({h['payload']['investigation_id'] for h in history if h['kind'] == 'investigation'})
        if linked:
            investigation = st.selectbox('Linked investigation', linked)
            evidence = OSINTRepository().get_evidence(investigation)
            if evidence:
                item = st.selectbox('Evidence', evidence, format_func=lambda e: str(e.get('id', e)))
                st.json(item)
                decision = st.selectbox('Decision', ['Accepted', 'Rejected', 'Needs review'])
                reviewer = st.text_input('Reviewer')
                annotation = st.text_area('Observation and supporting context')
                if st.button('Save review'):
                    if not reviewer.strip():
                        st.error('Reviewer is required')
                    else:
                        repo.append(key, 'review', {'investigation_id': investigation, 'evidence': item, 'decision': decision, 'reviewer': reviewer, 'annotation': annotation})
                        st.success('Review saved')
            else:
                st.info('No evidence in this investigation.')
        else:
            st.info('Link an investigation in Case record first.')
    with monitor:
        url = st.text_input('Public website URL')
        if st.button('Check website now'):
            try:
                with get_public_url(url, timeout=15, max_bytes=5_000_000) as response:
                    snapshot = {'url': url, 'final_url': response.url, 'status': response.status_code, 'sha256': hashlib.sha256(response.content).hexdigest()}
                previous = [h['payload'] for h in history if h['kind'] == 'website_check' and h['payload']['url'] == url]
                snapshot['changed'] = snapshot != {k: v for k, v in previous[-1].items() if k != 'changed'} if previous else None
                repo.append(key, 'website_check', snapshot)
                st.json(snapshot)
            except Exception as exc:
                repo.append(key, 'website_error', {'url': url, 'error': str(exc)})
                st.error(str(exc))
    with extraction:
        uploaded = st.file_uploader('Screenshot', type=['png', 'jpg', 'jpeg'])
        if uploaded and st.button('Extract text and QR contents'):
            try:
                from PIL import Image
                import cv2
                import numpy as np
                raw = uploaded.getvalue()
                picture = Image.open(io.BytesIO(raw))
                picture.load()
                result = {'source_sha256': hashlib.sha256(raw).hexdigest(), 'filename': uploaded.name}
                qr, _, _ = cv2.QRCodeDetector().detectAndDecode(cv2.cvtColor(np.array(picture.convert('RGB')), cv2.COLOR_RGB2BGR))
                result['qr_contents'] = qr
                if shutil.which('tesseract'):
                    with tempfile.TemporaryDirectory() as folder:
                        path = Path(folder) / 'input.png'
                        picture.save(path)
                        process = subprocess.run(['tesseract', str(path), 'stdout'], capture_output=True, text=True, timeout=60, check=True)
                        result['text'] = process.stdout
                else:
                    result['ocr_status'] = 'Unavailable: install the Tesseract executable'
                repo.append(key, 'extraction', result)
                st.json(result)
                st.caption('Check extracted text and decoded contents against the original image.')
            except Exception as exc:
                st.error(str(exc))
    with packages:
        files = st.file_uploader('Original artifacts and reports', accept_multiple_files=True)
        if st.button('Build evidence package'):
            try:
                names = [f.name for f in files]
                if len(names) != len(set(names)):
                    raise ValueError('File names must be unique')
                content = {f'artifacts/{f.name}': f.getvalue() for f in files}
                content['case.json'] = json.dumps({'case': case, 'activity': repo.activity(key)}, indent=2).encode()
                st.download_button('Download package', build_package(content), file_name='evidence.zip', mime='application/zip')
            except Exception as exc:
                st.error(str(exc))
        package = st.file_uploader('Verify an evidence ZIP', type=['zip'])
        if package and st.button('Verify package'):
            try:
                st.json(verify_package(package.getvalue()))
            except Exception as exc:
                st.error(f'Invalid package: {exc}')
        st.caption('Manifest hashes detect changes; they do not authenticate the package author.')
