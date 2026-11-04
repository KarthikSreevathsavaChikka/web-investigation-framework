import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from osint.llm_review import RelevanceReviewer, review_source, validate_review, collected_sources
from osint.normalizer import DomainNormalizer
from osint.storage import OSINTRepository
from osint.models import CollectorResult, Observation
from osint.coverage import summarize_coverage
from osint.cancellation import InvestigationCancelled
from osint.report import OSINTReportBuilder
from osint.docx_report import OSINTDocxReportBuilder


def decision(**overrides):
    return {'relevance': 'relevant', 'relationship': 'third_party_discussion', 'passage_ids': [1],
            'categories': ['payment'], 'reason': 'The passage discusses Example payments.',
            'candidate_links': [], **overrides}


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.target = DomainNormalizer.normalize('example.com')
        self.source = review_source('https://example.com/payments', 'Payments', 'Example payments',
                                    kind='page_excerpt', source_ref='evidence:1')

    def test_unknown_passages_links_and_fields_rejected(self):
        for value in [decision(passage_ids=[99]), decision(passage_ids=[True]), decision(passage_ids=[]),
                      decision(candidate_links=['https://invented.example']), decision(extra='injected'),
                      decision(categories=['guilty'])]:
            with self.assertRaises(ValueError):
                validate_review(value, self.source)
        self.assertEqual(validate_review(decision(relevance='unrelated'), self.source)['passage_ids'], [1])

    def test_exact_bounded_passages(self):
        text = ('ABC\n' * 1700)
        source = review_source('https://example.com', '', text, kind='document', source_ref='d1')
        self.assertEqual(''.join(p['text'] for p in source['passages']), text[:6000])
        self.assertTrue(source['truncated'])
        self.assertIsNone(review_source('https://example.com', '', '', kind='page', source_ref='p1'))

    @patch('osint.llm_review.requests.post')
    def test_valid_review_keeps_provenance_and_zero_risk(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {'model': 'server-model', 'choices': [{'message': {'content': json.dumps(decision())}}]}
        post.return_value = response
        reviewer = RelevanceReviewer()
        result = reviewer.run(self.target, [self.source], stage='content')
        observation = result.observations[0]
        self.assertEqual(result.status, 'COMPLETED')
        self.assertEqual(observation.risk_points, 0)
        self.assertEqual(observation.metadata['review_input']['source'], self.source)
        self.assertEqual(len(observation.metadata['input_sha256']), 64)
        self.assertEqual(observation.metadata['returned_model'], 'server-model')
        self.assertFalse(post.call_args.kwargs['allow_redirects'])
        constraint = post.call_args.kwargs['json']['response_format']
        self.assertEqual(constraint['type'], 'json_schema')
        self.assertTrue(constraint['json_schema']['strict'])
        self.assertEqual(constraint['json_schema']['schema']['properties']['passage_ids']['items']['enum'], [1])
        response.close.assert_called_once()

    def test_outage_keeps_uncertain_and_stops_after_two_failures(self):
        reviewer = RelevanceReviewer()
        sources = [{**self.source, 'source_url': f'https://example.com/{i}'} for i in range(5)]
        with patch.object(reviewer, 'review', side_effect=TimeoutError):
            result = reviewer.run(self.target, sources, stage='content')
        self.assertEqual(len(result.observations), 2)
        self.assertTrue(all(x.metadata['relevance'] == 'uncertain' for x in result.observations))
        self.assertEqual(result.status, 'PARTIAL')
        self.assertIn('3 outside budget', result.error)
        coverage = summarize_coverage([{'collector':'dns', 'status':'COMPLETED'},
                                       {'collector':result.collector, 'status':result.status}], [])
        self.assertEqual(coverage['status'], 'COMPLETED')

    def test_cancel_propagates(self):
        with self.assertRaises(InvestigationCancelled):
            RelevanceReviewer().run(self.target, [self.source], stage='content', cancel_check=lambda: True)

    def test_budget_dedup_and_ranking_preserve_candidates(self):
        reviewer = RelevanceReviewer()
        reviewer.budget = 1
        with patch.object(reviewer, 'review', return_value={**decision(), 'review_status':'reviewed'}):
            result = reviewer.run(self.target, [self.source, self.source, {**self.source,'source_url':'https://other.example'}], stage='discovery')
        self.assertEqual(len(result.observations), 1)
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory)/'test.db')
            repo.create_investigation('TEST', self.target)
            repo.save_collector_result('TEST', result)
            sources = [{'source_url':'https://other.example', 'source_type':'web'},
                       {'source_url':self.source['source_url'], 'source_type':'web'},
                       {'source_url':'https://example.com', 'source_type':'target_homepage'}]
            ranked = repo.prioritize_reviewed_sources('TEST', sources)
            self.assertEqual(len(ranked), 3)
            self.assertEqual(ranked[0]['source_type'], 'target_homepage')
            self.assertEqual(ranked[1]['source_url'], self.source['source_url'])

    def test_reviews_persist_and_exports_separate_advisory_text(self):
        reviewer = RelevanceReviewer()
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory)/'test.db')
            repo.create_investigation('TEST', self.target)
            with patch.object(reviewer, 'review', return_value={**decision(), 'review_status':'reviewed',
                     'model':'test-model', 'prompt_version':'v1', 'review_input':{'source':self.source}}):
                result = reviewer.run(self.target, [self.source], stage='content')
            repo.save_collector_result('TEST', result)
            self.assertEqual(repo.get_llm_reviews('TEST')[0]['relevance'], 'relevant')
            html = OSINTReportBuilder(repo).build_html('TEST')
            self.assertIn('AI relevance review', html)
            self.assertNotIn('LLM_RELEVANCE_REVIEW', html)
            self.assertTrue(OSINTDocxReportBuilder(repo).build('TEST').startswith(b'PK'))
            self.assertEqual(json.loads(OSINTReportBuilder(repo).build_json('TEST'))['ai_reviews'][0]['model'], 'test-model')

    def test_enabled_orchestrator_runs_both_stages(self):
        from osint.orchestrator import IntelligenceOrchestrator
        collector = Mock()
        collector.name = 'fixture'
        collector.collect.return_value = [Observation('fixture', 'Search', 'SEARCH_RESULT', 'Example payments',
            'https://example.com/payments', metadata={'query_id':'Q001', 'query_text':'Example', 'search_engine':'fixture',
            'rank':1, 'normalized_url':'https://example.com/payments', 'title':'Example payments',
            'snippet':'Example payments', 'source_type':'web'})]
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory)/'test.db')
            with patch.dict(os.environ, {'OSINT_LLM_REVIEW_ENABLED':'true'}), \
                 patch('osint.readiness.website_readiness', return_value={'status':'ready','reason':'Fixture access'}), \
                 patch('osint.readiness.llm_readiness', return_value={'status':'ready','reason':'Fixture model'}), \
                 patch.object(IntelligenceOrchestrator, 'COLLECTORS', {'Fixture':lambda:collector}), \
                 patch('osint.orchestrator.DomainIntelligenceService') as domains, \
                 patch('osint.orchestrator.PublicSearchResultCollector') as public, \
                 patch('osint.orchestrator.SERPEvidenceCapturePipeline') as pipeline, \
                 patch.object(RelevanceReviewer, 'review', return_value={**decision(), 'review_status':'reviewed',
                    'model':'test', 'prompt_version':'v1'}):
                domains.return_value.check_many.return_value = []
                public.SKIPPED_SOURCE_TYPES = set()
                public.return_value.collect.return_value = CollectorResult('public_search_results', 'COMPLETED')
                async def capture(*args, **kwargs):
                    return []
                pipeline.return_value.capture.side_effect = capture
                identifier = IntelligenceOrchestrator(repo).run('example.com', ['Fixture'])
            runs = {run['collector'] for run in repo.get_collector_runs(identifier)}
            self.assertIn('llm_relevance_discovery', runs)
            self.assertIn('llm_relevance_content', runs)
            self.assertTrue(repo.get_llm_reviews(identifier))
            self.assertEqual(repo.get_investigation(identifier)['risk_score'], 0)

    def test_social_platforms_are_interleaved_and_empty_sources_ignored(self):
        repo = Mock()
        repo.get_social_findings.return_value = [dict(id=i, platform=p, post_url='https://example.com', title=p, post_text=p)
                                                 for i,p in enumerate(['Facebook','Facebook','X'])]
        repo.get_documents.return_value = []
        repo.get_evidence.return_value = []
        repo.get_observations.return_value = []
        self.assertEqual([s['title'] for s in collected_sources(repo,'TEST')], ['Facebook','X','Facebook'])
