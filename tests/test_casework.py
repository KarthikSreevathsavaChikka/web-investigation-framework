import tempfile
import unittest
from pathlib import Path
from services.casework import CaseRepository
from services.case_analysis import compare_records, entity_graph


class CaseworkTests(unittest.TestCase):
    def test_case_history_survives_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'case.db'
            repo = CaseRepository(path)
            key = repo.create('REF-1', 'Example', 'Investigator')
            repo.append(key, 'note', {'text': 'Observed'})
            reopened = CaseRepository(path)
            self.assertEqual(reopened.list()[0]['reference'], 'REF-1')
            self.assertEqual(reopened.activity(key)[0]['payload']['text'], 'Observed')

    def test_comparison(self):
        result = compare_records([{'domain': 'old.example'}, {'domain': 'shared.example'}], [{'domain': 'new.example'}, {'domain': 'shared.example'}])
        self.assertEqual(result['retained'], ['shared.example'])
        self.assertEqual(result['added'], [{'domain': 'new.example'}])
        self.assertEqual(result['removed'], [{'domain': 'old.example'}])

    def test_graph_preserves_source(self):
        result = entity_graph([('case-1', [{'url': 'https://example.org/page'}])])
        self.assertEqual(result['edges'][0]['source_url'], 'https://example.org/page')
        self.assertEqual(result['edges'][0]['to'], 'example.org')
