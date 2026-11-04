import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from services.screenshot_groups import annotate_groups

class GroupTests(unittest.TestCase):
    def test_exact_duplicates_preserve_records(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            Image.new('RGB', (50, 50), 'red').save(root / 'a.png')
            (root / 'b.png').write_bytes((root / 'a.png').read_bytes())
            rows = [{'id': i, 'screenshot_path': str(root / p)} for i,p in enumerate(['a.png','b.png'])]
            annotate_groups(rows, root)
            self.assertEqual(rows[0]['screenshot_identity'], rows[1]['screenshot_identity'])
            self.assertEqual(rows[0]['screenshot_group'], rows[1]['screenshot_group'])
            self.assertEqual([r['id'] for r in rows], [0,1])

    def test_similarity_requires_source_context_and_dimensions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rows = []
            for i in range(5):
                path = root / str(i)
                path.write_bytes(b'x')
                rows.append({'screenshot_path': str(path), 'source_url': 'https://example.com', 'context_text': 'amount 100'})
            rows[2]['source_url'] = 'https://other.example'
            rows[3]['context_text'] = 'amount 999'
            with patch('services.screenshot_groups._fingerprint', side_effect=[('a',0,(100,100)),('b',1,(100,100)),('c',1,(100,100)),('d',1,(100,100)),('e',1,(200,100))]):
                annotate_groups(rows, root)
            self.assertEqual(rows[0]['screenshot_group'], rows[1]['screenshot_group'])
            for row in rows[2:]:
                self.assertNotEqual(row['screenshot_group'], rows[0]['screenshot_group'])

    def test_missing_files_stay_separate(self):
        with tempfile.TemporaryDirectory() as folder:
            rows = [{'screenshot_path': '/missing/a'}, {'screenshot_path': '/missing/b'}]
            annotate_groups(rows, Path(folder))
            self.assertNotEqual(rows[0]['screenshot_group'], rows[1]['screenshot_group'])
