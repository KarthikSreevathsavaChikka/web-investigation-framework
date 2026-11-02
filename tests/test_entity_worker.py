import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from services.entity_worker import index_pending
from services.entity_index import EntityIndex, entities

class Source:
    def __init__(self, path):
        self.db_path = path
    def list_investigations(self):
        return [{'id': 'internal', 'status': 'COMPLETED', 'completed_at': '2026-01-01'}, {'id': 'external', 'status': 'COMPLETED', 'completed_at': '2026-01-02'}, {'id': 'running', 'status': 'RUNNING'}]

class AutomaticIndexTests(unittest.TestCase):
    def test_historical_and_new_records_are_indexed_once(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Source(Path(folder) / 'db.sqlite')
            def process(repository, key):
                EntityIndex(repository.db_path).observe(key, 'https://' + key + '.example/contact', 'shared@example.org')
            with patch('services.entity_worker.enrich', side_effect=process) as enrich:
                index_pending(source)
                index_pending(source)
                self.assertEqual(enrich.call_count, 2)
            result = EntityIndex(source.db_path).results('internal')
            self.assertEqual(result['connections'][0]['investigation_id'], 'external')
            self.assertEqual(result['index_status']['status'], 'completed')

    def test_normalizes_international_phone_and_social_profile(self):
        result = entities('+91 98765 43210 https://t.me/example_handle')
        self.assertIn(('phone', '+919876543210'), result)
        self.assertIn(('social', 't.me/example_handle'), result)
