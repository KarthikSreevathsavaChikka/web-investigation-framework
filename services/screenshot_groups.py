"""Read-only presentation grouping; originals and evidence links remain intact."""
import hashlib
import re
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=512)
def _fingerprint(filename, size, modified):
    from PIL import Image
    path = Path(filename)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with Image.open(path) as image:
        if image.width * image.height > 25_000_000:
            return digest, None, None
        dimensions = image.size
        pixels = list(image.convert('L').resize((17, 16)).getdata())
        bits = 0
        for y in range(16):
            for x in range(16):
                bits = (bits << 1) | int(pixels[y * 17 + x] > pixels[y * 17 + x + 1])
    return digest, bits, dimensions


def annotate_groups(items, root):
    """Attach groups to temporary API records only, scoped to this invocation."""
    anchors = []
    exact = {}
    for i, item in enumerate(items):
        item['screenshot_group'] = str(i)
        item['screenshot_identity'] = str(i)
        try:
            path = Path(item.get('screenshot_path') or '').resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file():
                continue
            stat = path.stat()
            if stat.st_size > 20_000_000:
                continue
            digest, visual, dimensions = _fingerprint(str(path), stat.st_size, stat.st_mtime_ns)
        except (OSError, ValueError, ImportError):
            continue
        item['screenshot_identity'] = digest
        if digest in exact:
            item['screenshot_group'] = exact[digest]
            continue
        source = item.get('final_url') or item.get('source_url')
        # Require matching evidence context as an additional guard for altered values.
        context = re.sub(r'\s+', ' ', str(item.get('context_text') or item.get('evidence_text') or '')).strip()
        for group, old_source, old_context, old_visual, old_dimensions in anchors:
            if source and context and source == old_source and context == old_context and dimensions == old_dimensions and visual is not None and old_visual is not None and (visual ^ old_visual).bit_count() <= 3:
                item['screenshot_group'] = group
                break
        else:
            anchors.append((str(i), source, context, visual, dimensions))
        exact[digest] = item['screenshot_group']
