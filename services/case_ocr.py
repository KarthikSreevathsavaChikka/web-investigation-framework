"""Bounded image and PDF OCR with page references."""
import io
import subprocess
import tempfile
from pathlib import Path


def extract_document(raw):
    from PIL import Image
    import cv2
    import numpy as np
    pages = []
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        if raw.startswith(b'%PDF-'):
            import fitz
            with fitz.open(stream=raw, filetype='pdf') as document:
                if len(document) > 30:
                    raise ValueError('PDF exceeds 30 pages')
                for index, page in enumerate(document):
                    if page.rect.width * page.rect.height * 4 > 25_000_000:
                        raise ValueError('PDF page exceeds image size limit')
                    path = root / f'{index}.png'
                    page.get_pixmap(matrix=fitz.Matrix(2, 2)).save(path)
                    pages.append(path)
        else:
            with Image.open(io.BytesIO(raw)) as image:
                if image.width * image.height > 25_000_000:
                    raise ValueError('Image exceeds 25 megapixels')
                path = root / '0.png'
                image.convert('RGB').save(path)
                pages.append(path)
        results = []
        for index, path in enumerate(pages):
            text = subprocess.run(['tesseract', str(path), 'stdout'], capture_output=True, text=True, timeout=60, check=True).stdout
            image = cv2.imread(str(path))
            qr, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
            results.append({'page': index + 1, 'text': text, 'qr_contents': qr})
        return {'pages': results, 'text': '\n\n'.join(p['text'] for p in results)}
