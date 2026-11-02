import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch

from osint.collectors.brave_search import KeylessSearchCollector
from osint.dorks import DorkGenerator
from osint.models import NormalizedTarget, SearchResult, TargetResolution
from osint.orchestrator import IntelligenceOrchestrator
from osint.relevance import assess_serp_result, assess_page_relevance
from osint.search import SearchProvider
from osint.source_classifier import SourceClassifier
from osint.storage import OSINTRepository
from services.jobs.worker import execute_job


class AppProvider(SearchProvider):
    name = 'fixture'
    available = True

    def __init__(self, outcome='found'):
        self.outcome = outcome

    def search(self, query, *, query_id, count):
        if self.outcome == 'failed':
            raise RuntimeError('Search provider unavailable')
        if self.outcome == 'empty':
            return []
        return [SearchResult(query_id, query, self.name, 1, 'Sona Patti Android app',
                             'https://play.google.com/store/apps/details?id=test.sona',
                             'Sona Patti version 1.2 by Example Developer')]


class ApplicationDiscoveryTests(unittest.TestCase):
    def test_application_queries_include_entire_applicable_catalog(self):
        generator = DorkGenerator()
        entries = generator.load()
        queries = generator.generate(NormalizedTarget('Sonateenpatti', '', '', 'Sonateenpatti'))
        ids = {q.query_id for q in queries}
        texts = {q.query for q in queries}
        self.assertEqual(len(texts), len(queries))
        for entry in entries:
            if entry['enabled'] and entry['category'] != 'certificate_transparency':
                with patch.object(generator, 'load', return_value=[entry]):
                    rendered = generator.generate(NormalizedTarget('Sonateenpatti', '', '', 'Sonateenpatti'))
                self.assertTrue({q.query for q in rendered}.issubset(texts))
        for query in queries:
            self.assertIn('"Sonateenpatti"', query.query)
            self.assertNotIn('site:"Sonateenpatti"', query.query)
            self.assertNotIn('{}', query.query)
            self.assertTrue(query.category and query.priority and query.provider)
        self.assertIn('site:play.google.com/store/apps', next(q.query for q in queries if q.query_id == 'APP_003'))
        self.assertNotIn('Q048', ids)
        self.assertNotIn('Q049', ids)

    def test_name_matching_and_store_classification(self):
        target = NormalizedTarget('Sona Patti', '', '', 'Sona Patti')
        self.assertTrue(assess_serp_result(AppProvider().search('', query_id='A', count=1)[0], target).accepted)
        self.assertFalse(assess_page_relevance(target=target, visible_text='Other app', final_url='').accepted)
        for host in ('play.google.com', 'apps.apple.com', 'apkpure.com'):
            self.assertEqual(SourceClassifier.classify(f'https://{host}/app', ''), 'app_download')

    def test_worker_runs_name_only_investigation(self):
        resolution = TargetResolution('Sona Patti', 'sona patti', 'brand_or_app_name', 'Sona Patti')
        job = {'component': 'osint', 'payload': {'target': 'Sona Patti', 'collectors': ['DNS'], 'resolution': asdict(resolution)}}
        with patch('services.jobs.worker.IntelligenceOrchestrator') as orchestrator:
            orchestrator.return_value.run.return_value = 'OSINT_APP'
            result = execute_job(job)
        self.assertEqual(result['investigation_id'], 'OSINT_APP')
        self.assertEqual(orchestrator.return_value.run.call_args.args[0], 'Sona Patti')

    def test_search_scraping_and_storage_without_domain(self):
        for outcome in ('found', 'empty', 'failed'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                repo = OSINTRepository(Path(directory) / 'app.db')
                provider = AppProvider(outcome)
                provider.search = Mock(wraps=provider.search)
                collector = KeylessSearchCollector(provider)
                response = Mock()
                response.status_code = 200
                response.ok = True
                response.url = 'https://play.google.com/store/apps/details?id=test.sona'
                response.headers = {'Content-Type': 'text/html'}
                response.text = '<html><title>Sona Patti</title><body>Sona Patti Android app version 1.2 by Example Developer</body></html>'
                response.content = response.text.encode()
                with patch.dict(os.environ, {'OSINT_LLM_REVIEW_ENABLED': 'false', 'OSINT_EVIDENCE_SOURCE_BUDGET': '0', 'OSINT_SEARCH_REQUEST_DELAY': '0', 'OSINT_SOURCE_REQUEST_DELAY': '0'}), \
                     patch.object(IntelligenceOrchestrator, 'COLLECTORS', {'Keyless Web Search (no API key)': lambda: collector}), \
                     patch('osint.readiness.website_readiness') as website, \
                     patch('osint.collectors.results.get_public_url', return_value=response) as fetch:
                    identifier = IntelligenceOrchestrator(repo).run('Sona Patti', ['DNS', 'Public website'],
                        resolution=TargetResolution('Sona Patti', 'sona patti', 'brand_or_app_name', 'Sona Patti'),
                        query_budget=12)
                website.assert_not_called()
                investigation = repo.get_investigation(identifier)
                self.assertEqual(investigation['status'], 'COMPLETED')
                self.assertEqual(investigation['target_domain'], '')
                self.assertEqual(investigation['resolution_confidence'], 0.0)
                self.assertEqual(repo.get_candidates(identifier), [])
                queries = repo.get_queries(identifier)
                self.assertGreater(len(queries), 12)
                self.assertEqual(provider.search.call_count, len(queries))
                self.assertTrue(all('Sona Patti' in q['query'] for q in queries))
                observations = repo.get_observations(identifier)
                diagnostic = next(o for o in observations if o['entity_type'] == 'APPLICATION_DISCOVERY')
                if outcome == 'found':
                    fetch.assert_called_once()
                    self.assertEqual(len(repo.get_sources(identifier)), 1)
                    self.assertTrue(any(o['entity_type'] == 'PUBLIC_PAGE_METADATA' for o in observations))
                else:
                    fetch.assert_not_called()
                    self.assertIn('incomplete' if outcome == 'failed' else 'No relevant app information', diagnostic['value'])


if __name__ == '__main__':
    unittest.main()
