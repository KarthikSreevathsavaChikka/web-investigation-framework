import json
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from docx import Document

from osint.cancellation import InvestigationCancelled
from osint.coverage import observation_has_gap, summarize_coverage
from osint.docx_report import OSINTDocxReportBuilder
from osint.models import CollectorResult, Observation, PageCaptureRecord
from osint.normalizer import DomainNormalizer
from osint.orchestrator import IntelligenceOrchestrator
from osint.readiness import llm_readiness, run_readiness, session_readiness, website_readiness
from osint.report import OSINTReportBuilder
from osint.storage import OSINTRepository
from osint.text_cleanup import social_screenshot_context


class ReadinessTests(unittest.TestCase):
    def test_saved_state_is_configuration_not_proof_of_login(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.json'
            self.assertEqual(session_readiness(path)['status'], 'unavailable')
            for text in ('invalid JSON', '{}', '{"cookies":"secret"}', '{"cookies":[null]}', '{"origins":[null]}'):
                path.write_text(text)
                self.assertEqual(session_readiness(path)['status'], 'unavailable')
            path.write_text(json.dumps({'cookies': [{'name': 'session', 'value': 'SECRET_TOKEN', 'domain': '.x.com'}]}))
            result = session_readiness(path)
            self.assertEqual(result['status'], 'configured')
            self.assertNotIn('SECRET_TOKEN', json.dumps(result))

    @patch('osint.readiness.requests.get')
    def test_model_probe_checks_selected_model_without_redirecting(self, get):
        response = get.return_value.__enter__.return_value
        response.status_code = 200
        response.json.return_value = {'data': [{'id': 'fixture-model'}]}
        with patch.dict(os.environ, {'LM_STUDIO_BASE_URL': 'http://10.244.1.54:1234/v1/chat/completions', 'LM_STUDIO_MODEL': 'fixture-model'}):
            self.assertEqual(llm_readiness()['status'], 'ready')
            self.assertEqual(get.call_args.args[0], 'http://10.244.1.54:1234/v1/models')
            self.assertFalse(get.call_args.kwargs['allow_redirects'])
            response.json.return_value = {'data': [{'id': 'other-model'}]}
            self.assertEqual(llm_readiness()['status'], 'unavailable')
            response.status_code = 401
            self.assertIn('401', llm_readiness()['reason'])

    def test_unreachable_website_keeps_browser_fallback_and_closes_response(self):
        target = DomainNormalizer.normalize('example.com/en/')
        with patch('osint.readiness.get_public_url', side_effect=requests.ConnectionError):
            check = website_readiness(target, 10)
        self.assertEqual(check['status'], 'limited')
        self.assertIn('Browser capture will still be attempted', check['reason'])
        response = Mock(status_code=403, text='Access denied')
        with patch('osint.readiness.get_public_url', return_value=response):
            self.assertEqual(website_readiness(target, 10)['status'], 'limited')
        response.close.assert_called_once()

    def test_invalid_model_address_does_not_abort_collection(self):
        for address in ('http://[broken', 'http://server:badport'):
            with patch.dict(os.environ, {'LM_STUDIO_BASE_URL': address}):
                self.assertEqual(llm_readiness()['status'], 'unavailable')

    def test_script_captcha_reference_is_not_a_visible_access_challenge(self):
        response = Mock(status_code=200, text='<html><script src="recaptcha.js"></script><body>Example home</body></html>')
        with patch('osint.readiness.get_public_url', return_value=response):
            self.assertEqual(website_readiness(DomainNormalizer.normalize('example.com'), 5)['status'], 'ready')

    def test_screenshot_text_uses_its_original_capture_scope(self):
        finding = {'search_snippet': 'Original search card', 'post_text': 'Full individual post',
                   'screenshot_provenance': [{'path': 'search.png', 'scope': 'search_results'},
                                             {'path': 'post.png', 'scope': 'post_container'}]}
        self.assertEqual(social_screenshot_context(finding, 'search.png')['text'], 'Original search card')
        self.assertEqual(social_screenshot_context(finding, 'post.png')['text'], 'Full individual post')

    def test_readiness_cancellation_prevents_network_work(self):
        with patch('osint.readiness.website_readiness') as website:
            with self.assertRaises(InvestigationCancelled):
                run_readiness(DomainNormalizer.normalize('example.com'), [], cancel_check=lambda: True)
        website.assert_not_called()

    def test_preflight_and_non_page_skips_do_not_override_actual_coverage(self):
        coverage = summarize_coverage([
            {'collector': 'collection_readiness', 'status': 'PARTIAL'},
            {'collector': 'public_web', 'status': 'COMPLETED'},
        ], [{'accessibility_status': 'baseline_captured'}, {'accessibility_status': 'skipped_non_content'}])
        self.assertEqual(coverage['status'], 'COMPLETED')
        self.assertEqual(coverage['skipped_non_content'], 1)
        self.assertEqual(coverage['unavailable_pages'], 0)
        self.assertTrue(observation_has_gap(Observation('social', '', 'SOCIAL_COLLECTION_DIAGNOSTIC', '', '', metadata={'extraction_errors': 1})))


class QualityIntegrationTests(unittest.TestCase):
    def test_assets_do_not_consume_ai_budget_and_worker_context_is_exported(self):
        target = DomainNormalizer.normalize('https://example.com/en/?source=Official')
        urls = ['https://example.com/site.css', 'https://example.com/image?format=webp',
                'https://example.com/review']
        collector = Mock()
        collector.name = 'fixture'
        collector.collect.return_value = [Observation('fixture', 'Search', 'SEARCH_RESULT', 'Example text', url, metadata={
            'query_id': 'B002', 'query_text': 'Example reviews', 'search_engine': 'fixture', 'rank': n,
            'normalized_url': url, 'title': 'Example reviews', 'snippet': 'Example withdrawal experience.', 'source_type': 'web',
        }) for n, url in enumerate(urls, 1)]
        collector.collect.return_value.append(Observation('public_web', 'Identity', 'BRAND_ALIAS', 'Example Brand', target.url,
            metadata={'evidence_field': 'meta:og:site_name', 'evidence_text': 'Example Brand'}))
        captured_tasks = []

        async def capture(_id, _domain, tasks, _brand, **kwargs):
            captured_tasks.extend(tasks)
            return [PageCaptureRecord(source_id=t['source_id'], source_url=t['source_url'], accessibility_status='baseline_captured') for t in tasks]

        def review(_target, source, timeout, **kwargs):
            self.assertNotIn('.css', source['source_url'])
            self.assertNotIn('format=webp', source['source_url'])
            self.assertEqual(kwargs['profile']['aliases'][0]['value'], 'Example Brand')
            return {'relevance': 'relevant', 'relationship': 'complaint', 'passage_ids': [1],
                    'categories': ['complaint'], 'reason': 'Source describes Example withdrawal.', 'candidate_links': [],
                    'review_status': 'reviewed', 'model': 'fixture', 'prompt_version': 'fixture'}

        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'test.db')
            with patch.dict(os.environ, {'OSINT_LLM_REVIEW_ENABLED': 'true', 'OSINT_LLM_REVIEW_BUDGET': '1'}), \
                 patch.object(IntelligenceOrchestrator, 'COLLECTORS', {'Fixture': lambda: collector}), \
                 patch('osint.readiness.website_readiness', return_value={'status': 'limited', 'reason': 'HTTP probe failed'}), \
                 patch('osint.readiness.llm_readiness', return_value={'status': 'ready', 'reason': 'Fixture model'}), \
                 patch('osint.orchestrator.DomainIntelligenceService') as domains, \
                 patch('osint.orchestrator.PublicSearchResultCollector') as public, \
                 patch('osint.orchestrator.SERPEvidenceCapturePipeline') as pipeline, \
                 patch('osint.llm_review.RelevanceReviewer.review', side_effect=review):
                domains.return_value.check_many.return_value = []
                public.SKIPPED_SOURCE_TYPES = set()
                public.return_value.collect.return_value = CollectorResult('public_search_results', 'COMPLETED')
                pipeline.return_value.capture.side_effect = capture
                identifier = IntelligenceOrchestrator(repo).run(target.url, ['Fixture'], brand='Example')
            self.assertIn(target.url, [t['source_url'] for t in captured_tasks])
            self.assertTrue(all('.css' not in t['source_url'] and 'format=webp' not in t['source_url'] for t in captured_tasks))
            diagnostics = repo.get_collection_diagnostics(identifier)
            self.assertEqual(len(diagnostics['source_selection']['excluded_from_page_and_text_review']), 2)
            self.assertEqual(diagnostics['readiness']['execution_location'], 'investigation_worker')
            self.assertEqual(len(repo.get_llm_reviews(identifier)), 1)
            self.assertEqual(repo.get_investigation(identifier)['risk_score'], 0)
            self.assertIn('Worker readiness', OSINTReportBuilder(repo).build_html(identifier))
            self.assertIn('collection_diagnostics', json.loads(OSINTReportBuilder(repo).build_json(identifier)))
            document = Document(BytesIO(OSINTDocxReportBuilder(repo).build(identifier)))
            self.assertIn('Worker readiness', [p.text for p in document.paragraphs])

    def test_social_detail_metadata_survives_storage_without_overwriting_post_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'test.db')
            repo.create_investigation('TEST', DomainNormalizer.normalize('example.com'))
            post = Observation('x_authenticated_playwright', 'Social', 'AUTOMATED_SOCIAL_FINDING', 'Example',
                'https://x.com/author/status/123', metadata={'platform': 'X', 'post_text': 'Exact original post text.',
                'content_scope': 'post_text', 'capture_status': 'captured', 'author': 'Author',
                'published_at': '2026-09-09T00:00:00Z', 'search_snippet': 'Original card snippet',
                'screenshot_provenance': [{'path': 'post.png', 'scope': 'post_container'}]})
            repo.save_collector_result('TEST', CollectorResult('x_authenticated_playwright', 'COMPLETED', [post]))
            finding = repo.get_social_findings('TEST')[0]
            self.assertEqual(finding['post_url'], post.source_url)
            self.assertEqual(finding['post_text'], 'Exact original post text.')
            self.assertEqual(finding['search_snippet'], 'Original card snippet')
            self.assertEqual(finding['screenshot_provenance'][0]['scope'], 'post_container')


if __name__ == '__main__':
    unittest.main()
