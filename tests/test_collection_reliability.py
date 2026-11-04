import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import requests
import yaml

from osint.coverage import summarize_coverage
from osint.collectors.results import PublicSearchResultCollector
from osint.dorks import DorkGenerator
from osint.evidence_capture import SERPEvidenceCapturePipeline
from osint.http import get_public_url, UnsafeTargetError
from osint.models import CollectorResult, Observation, PageCaptureRecord, SearchResult
from osint.normalizer import DomainNormalizer
from osint.orchestrator import IntelligenceOrchestrator, public_social_capture_tasks
from osint.report import OSINTReportBuilder
from osint.docx_report import OSINTDocxReportBuilder
from osint.search import AggregatingSearchProvider, DuckDuckGoSearchProvider, SearXNGSearchProvider
from osint.storage import OSINTRepository
from osint.url_tools import is_content_page_url


class CollectionCoverageTests(unittest.TestCase):
    def test_dns_success_does_not_hide_failed_collection(self):
        result = summarize_coverage([
            dict(collector='dns', status='COMPLETED'),
            dict(collector='search', status='PARTIAL'),
        ], [dict(accessibility_status='failed')])
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['usable_pages'], 0)
        self.assertEqual(result['incomplete_collectors'], ['search'])

    def test_relevance_rejection_is_a_completed_check(self):
        self.assertEqual(summarize_coverage([dict(collector='search', status='COMPLETED')],
                         [dict(accessibility_status='rejected_irrelevant')])['status'], 'COMPLETED')
        self.assertEqual(summarize_coverage([], [])['status'], 'PARTIAL')

    @patch('osint.collectors.results.get_public_url', side_effect=requests.ConnectionError('reset'))
    def test_source_failure_is_partial(self, get):
        with patch('osint.collectors.results.time.sleep'):
            result = PublicSearchResultCollector().collect(DomainNormalizer.normalize('example.com'),
                     [dict(source_url='https://example.com/page')], 3, 'TEST')
        self.assertEqual(result.status, 'PARTIAL')

    def test_orchestrator_persists_partial_and_reports_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'test.db')
            collector = Mock(name='test_collector')
            collector.name = 'test'
            collector.collect.return_value = []
            async def failed_capture(_id, _domain, tasks, _brand, **kwargs):
                return [PageCaptureRecord(source_id=t['source_id'], source_url=t['source_url'],
                                          accessibility_status='failed', failure_reason='connection reset') for t in tasks]
            with patch.object(IntelligenceOrchestrator, 'COLLECTORS', {'Test': lambda: collector}), \
                 patch('osint.readiness.website_readiness', return_value={'status':'ready','reason':'Fixture access'}), \
                 patch('osint.readiness.llm_readiness', return_value={'status':'ready','reason':'Fixture model'}), \
                 patch('osint.orchestrator.DomainIntelligenceService') as domains, \
                 patch('osint.orchestrator.SERPEvidenceCapturePipeline') as pipeline:
                domains.return_value.check_many.return_value = []
                pipeline.return_value.capture.side_effect = failed_capture
                identifier = IntelligenceOrchestrator(repo).run('example.com', ['Test'])
            investigation = repo.get_investigation(identifier)
            self.assertEqual(investigation['status'], 'COMPLETED')
            self.assertEqual(investigation['coverage']['status'], 'PARTIAL')
            self.assertEqual(investigation['coverage']['unavailable_pages'], 1)
            html = OSINTReportBuilder(repo).build_html(identifier)
            self.assertIn('zero score is not a safety finding', html)
            self.assertIn('Collection coverage: PARTIAL', html)
            self.assertTrue(OSINTDocxReportBuilder(repo).build(identifier).startswith(b'PK'))


class SourceSelectionTests(unittest.TestCase):
    def test_downloaded_html_omits_rejected_search_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = OSINTRepository(Path(directory) / "test.db")
            target = DomainNormalizer.normalize("example.com")
            repository.create_investigation("REPORT_NO_NOISE", target)
            repository.save_collector_result("REPORT_NO_NOISE", CollectorResult("search", "COMPLETED", [
                Observation("search", "Search", "SEARCH_RESULT_REJECTED", "Unrelated result",
                            "https://unrelated.example/page", metadata={
                                "query_id": "Q1", "query_text": "example", "search_engine": "test",
                                "rank": 1, "normalized_url": "https://unrelated.example/page",
                                "source_type": "webpage", "relevance_status": "rejected_irrelevant",
                                "relevance_reason": "No target identity",
                            }),
            ]))
            html = OSINTReportBuilder(repository).build_html("REPORT_NO_NOISE")
            self.assertNotIn("Rejected search noise", html)
            self.assertNotIn("Unrelated result", html)

    def test_public_social_findings_receive_separate_capture_tasks(self):
        repository = Mock()
        repository.get_social_findings.return_value = [
            {"post_url": "https://reddit.com/r/test/?utm_source=search", "capture_status": None},
            {"post_url": "https://x.com/example/status/1", "capture_status": "captured"},
            {"post_url": "invalid", "capture_status": None},
        ]
        repository.get_evidence_tasks.return_value = [
            {"source_id": 1, "normalized_url": "https://reddit.com/r/test"},
            {"source_id": 2, "normalized_url": "https://example.com/"},
        ]
        self.assertEqual(public_social_capture_tasks(repository, "TEST", 8), [
            {"source_id": 1, "normalized_url": "https://reddit.com/r/test"},
        ])
        repository.get_evidence_tasks.assert_called_once_with("TEST", 10_000)

    def test_asset_suffixes_ignore_case_encoding_and_query(self):
        for url in ['https://example.com/index.CSS?v=1', 'https://example.com/a%2Ejs', 'https://example.com/a.woff2']:
            self.assertFalse(is_content_page_url(url), url)
        for url in ['https://example.com/payment/', 'https://example.com/report.pdf', 'https://example.com/view?id=5']:
            self.assertTrue(is_content_page_url(url), url)

    def test_assets_do_not_consume_budget_and_homepage_is_first(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'test.db')
            target = DomainNormalizer.normalize('example.com')
            queries = DorkGenerator().generate(target)
            repo.create_investigation('TEST', target)
            repo.save_queries('TEST', queries)
            observations = []
            for rank, path in enumerate(['first.css', 'second.js', 'payment'], 1):
                url = f'https://example.com/{path}'
                observations.append(Observation('search', 'Search', 'SEARCH_RESULT', path, url, metadata={
                    'query_id': queries[0].query_id, 'query_text': queries[0].query, 'search_engine': 'test',
                    'rank': rank, 'normalized_url': url, 'source_type': 'webpage',
                }))
            repo.save_collector_result('TEST', CollectorResult('search', 'COMPLETED', observations))
            repo.ensure_first_party_source('TEST', target, queries)
            tasks = repo.get_evidence_tasks('TEST', 2)
            self.assertEqual(len(tasks), 2)
            self.assertTrue(tasks[0]['first_party_seed'])
            self.assertEqual(tasks[0]['document_priority'], 0)
            self.assertTrue(tasks[1]['source_url'].endswith('/payment'))
            self.assertEqual(repo.get_evidence_tasks('TEST', 0), [])


class ProviderReliabilityTests(unittest.TestCase):
    @patch('osint.search.requests.get')
    @patch('osint.search.BraveSearchProvider._init_cache')
    def test_searxng_partial_results_retain_failure_diagnostics(self, cache, get):
        get.return_value.json.return_value = {'results': [dict(url='https://example.com', title='Example')],
                                            'unresponsive_engines': [['duckduckgo', 'timeout']]}
        provider = SearXNGSearchProvider('http://searxng:8080')
        provider.cache_ttl = 0
        aggregate = AggregatingSearchProvider([provider])
        results = aggregate.search('example', query_id='Q1', count=10)
        self.assertEqual(len(results), 1)
        self.assertIn('timeout', aggregate.execution_reports('Q1')[0].error)
        get.return_value.json.return_value['results'] = []
        with self.assertRaisesRegex(RuntimeError, 'upstream failures'):
            provider.search('example', query_id='Q2', count=10)

    @patch('osint.search.requests.get')
    @patch('osint.search.BraveSearchProvider._init_cache')
    def test_duckduckgo_challenge_is_not_empty_success(self, cache, get):
        get.return_value.text = '<form action="/anomaly.js">Solve challenge</form>'
        provider = DuckDuckGoSearchProvider()
        provider.cache_ttl = 0
        with self.assertRaisesRegex(RuntimeError, 'challenge'):
            provider.search('example', query_id='Q1', count=10)

    def test_provider_recovers_after_cooldown(self):
        provider = Mock()
        provider.name = 'test'
        provider.available = True
        provider.last_error = None
        provider.search.side_effect = [requests.Timeout('timeout'), []]
        aggregate = AggregatingSearchProvider([provider])
        with patch('osint.search.time.monotonic', return_value=100):
            with self.assertRaises(RuntimeError):
                aggregate.search('one', query_id='Q1', count=1)
            with self.assertRaises(RuntimeError):
                aggregate.search('two', query_id='Q2', count=1)
        with patch('osint.search.time.monotonic', return_value=131):
            self.assertEqual(aggregate.search('three', query_id='Q3', count=1), [])
        self.assertEqual(provider.search.call_count, 2)

    def test_compose_passes_collection_settings_to_both_consumers(self):
        compose = yaml.safe_load(Path('compose.yaml').read_text())
        for service in ['app', 'worker']:
            env = compose['services'][service]['environment']
            for key in ['BRAVE_SEARCH_API_KEY', 'SIMILARWEB_API_KEY', 'OSINT_EVIDENCE_SOURCE_BUDGET', 'OSINT_DISABLE_SEARXNG']:
                self.assertIn(key, env)


class TransportTests(unittest.TestCase):
    @patch('osint.http.time.sleep')
    @patch('osint.http.DomainNormalizer.public_addresses', return_value=['93.184.216.34'])
    @patch('osint.http.requests.get')
    def test_one_transient_retry_preserves_redirect_validation(self, get, addresses, sleep):
        response = Mock(is_redirect=False, is_permanent_redirect=False)
        get.side_effect = [requests.ConnectionError('reset'), response]
        self.assertIs(get_public_url('https://example.com', timeout=3), response)
        self.assertEqual(get.call_count, 2)
        self.assertFalse(get.call_args.kwargs['allow_redirects'])

    @patch('osint.http.DomainNormalizer.public_addresses', return_value=[])
    @patch('osint.http.requests.get')
    def test_unsafe_destination_is_never_requested(self, get, addresses):
        with self.assertRaises(UnsafeTargetError):
            get_public_url('https://internal.example', timeout=3)
        get.assert_not_called()

    def test_queued_pages_do_not_exhaust_capture_deadline(self):
        async def run():
            pipeline = SERPEvidenceCapturePipeline(Path('/tmp'))
            pipeline.source_timeout_seconds = 0.05
            async def capture(*args):
                await asyncio.sleep(0.025)
                task = args[4]
                return PageCaptureRecord(source_id=task['source_id'], source_url=task['source_url'],
                                         accessibility_status='baseline_captured')
            pipeline._capture_source = capture
            semaphore = asyncio.Semaphore(1)
            return await asyncio.gather(*[
                pipeline._capture_source_with_timeout(None, semaphore, 'TEST', 'example.com',
                    dict(source_id=i, source_url='https://example.com')) for i in range(4)
            ])
        self.assertTrue(all(item.accessibility_status == 'baseline_captured' for item in asyncio.run(run())))

    def test_navigation_retries_reset_but_not_block(self):
        async def run():
            pipeline = SERPEvidenceCapturePipeline(Path('/tmp'))
            page = Mock()
            response = Mock(status=403)
            page.goto = AsyncMock(side_effect=[RuntimeError('net::ERR_CONNECTION_RESET'), response])
            with patch('osint.evidence_capture.asyncio.sleep', new_callable=AsyncMock):
                self.assertIs(await pipeline._navigate_page(page, 'https://example.com'), response)
            self.assertEqual(page.goto.await_count, 2)
        asyncio.run(run())

    def test_navigation_keeps_committed_page_when_dom_event_is_delayed(self):
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
        async def run():
            pipeline = SERPEvidenceCapturePipeline(Path('/tmp'))
            page = Mock()
            response = Mock(status=200)
            page.goto = AsyncMock(return_value=response)
            page.wait_for_load_state = AsyncMock(side_effect=PlaywrightTimeoutError('slow scripts'))
            self.assertIs(await pipeline._navigate_page(page, 'https://example.com'), response)
            page.goto.assert_awaited_once_with('https://example.com', wait_until='commit', timeout=pipeline.timeout_ms)
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
