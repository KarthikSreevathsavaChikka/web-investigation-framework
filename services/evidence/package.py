"""Portable evidence bundles with explicit SHA-256 verification.

Hashes detect changes relative to the manifest; they do not authenticate its author.
"""
import hashlib
import io
import json
import zipfile
from pathlib import PurePosixPath

MAX_TOTAL_BYTES = 200 * 1024 * 1024


def _valid_name(name):
    path = PurePosixPath(name)
    return bool(name and not path.is_absolute() and '..' not in path.parts
                and '\\' not in name and name != 'manifest.json')


def build_package(files: dict[str, bytes]) -> bytes:
    """Bundle caller-selected originals and reports without altering their bytes."""
    if any(not _valid_name(name) for name in files):
        raise ValueError('Invalid or reserved artifact name')
    if sum(map(len, files.values())) > MAX_TOTAL_BYTES:
        raise ValueError('Evidence package exceeds 200 MiB')
    manifest = {'version': 1, 'algorithm': 'sha256', 'files': {
        name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())}}
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
        archive.writestr('manifest.json', json.dumps(manifest, indent=2))
    return output.getvalue()


def verify_package(data: bytes) -> dict:
    """Verify in memory without extracting paths from an untrusted archive."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError('Duplicate archive entries')
        if sum(item.file_size for item in entries) > MAX_TOTAL_BYTES:
            raise ValueError('Expanded package exceeds 200 MiB')
        manifest = json.loads(archive.read('manifest.json'))
        if manifest.get('version') != 1 or manifest.get('algorithm') != 'sha256':
            raise ValueError('Unsupported manifest')
        expected = manifest['files']
        if not isinstance(expected, dict) or any(not _valid_name(n) for n in expected):
            raise ValueError('Invalid manifest files')
        actual = set(names) - {'manifest.json'}
        missing = sorted(set(expected) - actual)
        unexpected = sorted(actual - set(expected))
        altered = []
        for name in sorted(actual & set(expected)):
            content = archive.read(name)
            record = expected[name]
            if (len(content) != record['size'] or
                    hashlib.sha256(content).hexdigest() != record['sha256']):
                altered.append(name)
        return {'valid': not (missing or unexpected or altered),
                'missing': missing, 'unexpected': unexpected, 'altered': altered}
