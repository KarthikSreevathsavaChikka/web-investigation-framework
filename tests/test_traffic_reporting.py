import json
import os
import tempfile
import unittest
from datetime import date, datetime, timezone, timedelta
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from docx import Document

from osint.domain_intelligence import DomainCheck, DomainIntelligenceService, SimilarwebTrafficProvider, summarize_monthly_visits
from osint.models import NormalizedTarget
from osint.report import OSINTReportBuilder
from osint.docx_report import OSINTDocxReportBuilder
from osint.storage import OSINTRepository


class TrafficCalculationTests(unittest.TestCase):
    def test_sorted_twelve_distinct_consecutive_months_are_a_year_estimate(self):
        months = [f'2025-{month:02}' for month in range(9, 13)] + [f'2026-{month:02}' for month in range(1, 9)]
        data = [{'date': month, 'visits': (index + 1) * 100} for index, month in enumerate(months)]
        result = summarize_monthly_visits(list(reversed(data)), today=date(2026, 9, 10))
        self.assertEqual(result['monthly_visits'], 1200)
        self.assertEqual(result['yearly_visits'], 7800)
        self.assertEqual(result['yearly_visits_kind'], '12-month estimate')
        self.assertEqual(result['traffic_data_date'], '2026-08')

    def test_duplicates_and_missing_months_cannot_look_like_a_complete_year(self):
        result = summarize_monthly_visits([{'date': '2026-08-01', 'visits': 100}] * 12, today=date(2026, 9, 10))
        self.assertEqual(result['yearly_visits_kind'], 'Projected')
        self.assertEqual(result['yearly_visits'], 1200)

    def test_zero_is_valid_but_missing_is_not_zero(self):
        zero = summarize_monthly_visits([{'date': '2026-08', 'visits': 0}], today=date(2026, 9, 10))
        missing = summarize_monthly_visits([{'date': '2026-08', 'visits': None}], today=date(2026, 9, 10))
        self.assertEqual(zero['monthly_visits'], 0)
        self.assertIsNone(missing['monthly_visits'])
        self.assertEqual(missing['traffic_status'], 'no_data')

    def test_invalid_numbers_and_undated_series_are_rejected(self):
        for item in [{'date': '2026-08', 'visits': value} for value in (-1, True, 'NaN', 'Infinity')] + [{'visits': 100}]:
            with self.assertRaises(ValueError):
                summarize_monthly_visits([item], today=date(2026, 9, 10))

    def test_current_incomplete_month_is_excluded(self):
        result = summarize_monthly_visits([{'date': '2026-09', 'visits': 999}, {'date': '2026-08', 'visits': 50}], today=date(2026, 9, 10))
        self.assertEqual(result['monthly_visits'], 50)

    def test_api_parameters_and_connection_cleanup(self):
        response = Mock(status_code=200)
        response.json.return_value = {'visits': [{'date': '2025-01', 'visits': 500}]}
        request = Mock(return_value=response)
        with patch.dict(os.environ, {'TRAFFIC_PROVIDER': 'similarweb'}):
            result = SimilarwebTrafficProvider('key', request=request).lookup('www.example.com')
        self.assertIn('/website/example.com/', request.call_args.args[0])
        params = request.call_args.kwargs['params']
        self.assertEqual(params['country'], 'world')
        self.assertEqual(params['granularity'], 'monthly')
        self.assertRegex(params['start_date'], r'^\d{4}-\d{2}$')
        self.assertFalse(request.call_args.kwargs['allow_redirects'])
        self.assertEqual(result['monthly_visits'], 500)
        response.close.assert_called_once()

    def test_errors_do_not_expose_api_key_and_missing_configuration_is_explicit(self):
        with patch.dict(os.environ, {'TRAFFIC_PROVIDER': 'similarweb', 'SIMILARWEB_API_KEY': ''}):
            missing = SimilarwebTrafficProvider().lookup('example.com')
            self.assertEqual(missing['traffic_status'], 'not_configured')
            provider = SimilarwebTrafficProvider('SECRET', request=Mock(side_effect=requests.Timeout('https://provider?api_key=SECRET')))
            error = provider.lookup('example.com')
            self.assertNotIn('SECRET', json.dumps(error))
            self.assertEqual(error['traffic_status'], 'unavailable')


class TrafficPersistenceTests(unittest.TestCase):
    def test_traffic_does_not_depend_on_target_dns(self):
        provider = Mock()
        provider.lookup.return_value = {'monthly_visits': 123, 'yearly_visits': 1476, 'traffic_status': 'available'}
        check = DomainIntelligenceService(traffic_provider=provider, public_host=lambda _: False).check('example.com')
        self.assertEqual(check.http_status, 'DNS Failed')
        self.assertEqual(check.monthly_visits, 123)
        provider.lookup.assert_called_once_with('example.com')

    def test_empty_cache_is_retried_and_fresh_success_is_reused(self):
        provider = Mock()
        provider.lookup.return_value = {'monthly_visits': 500}
        service = DomainIntelligenceService(traffic_provider=provider)
        service.lookup_traffic('example.com', {'monthly_visits': None, 'refreshed_at': datetime.now(timezone.utc).isoformat()})
        provider.lookup.assert_called_once()
        provider.lookup.reset_mock()
        cache = {'monthly_visits': 100, 'traffic_data_date': '2026-08', 'refreshed_at': datetime.now(timezone.utc).isoformat()}
        self.assertEqual(service.lookup_traffic('example.com', cache)['traffic_status'], 'cached')
        provider.lookup.assert_not_called()

    def test_failed_refresh_keeps_old_estimate_with_original_timestamp(self):
        provider = Mock()
        provider.lookup.return_value = {'monthly_visits': None, 'traffic_error': 'Rate limited'}
        timestamp = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        cached = {'monthly_visits': 100, 'yearly_visits': 1200, 'traffic_data_date': '2026-08', 'refreshed_at': timestamp}
        result = DomainIntelligenceService(traffic_provider=provider).lookup_traffic('example.com', cached)
        self.assertEqual(result['traffic_status'], 'stale')
        self.assertEqual(result['monthly_visits'], 100)
        self.assertEqual(result['traffic_refreshed_at'], timestamp)
        self.assertEqual(result['traffic_error'], 'Rate limited')

    def test_traffic_only_update_preserves_http_results_and_exports_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'test.db')
            repo.create_investigation('TEST', NormalizedTarget('example.com', 'example.com', 'https://example.com'))
            repo.save_domain_checks('TEST', [DomainCheck('example.com', domain_status='Active', http_status='403', checked_at='2026-09-10')])
            values = summarize_monthly_visits([{'date': '2026-08', 'visits': 3_000_000_000}], today=date(2026, 9, 10))
            repo.save_traffic_results('TEST', [{'domain': 'example.com', **values}])
            item = repo.get_candidates('TEST')[0]
            self.assertEqual(item['http_status'], '403')
            self.assertEqual(item['checked_at'], '2026-09-10')
            self.assertEqual(item['monthly_visits'], 3_000_000_000)
            html = OSINTReportBuilder(repo).build_html('TEST')
            self.assertIn('2026-08', html)
            self.assertIn('Projected', html)
            self.assertIn('traffic_error', OSINTReportBuilder(repo).build_domain_csv('TEST'))
            paragraphs = [p.text for p in Document(BytesIO(OSINTDocxReportBuilder(repo).build('TEST'))).paragraphs]
            self.assertTrue(any('Traffic for example.com: available' in text for text in paragraphs))


if __name__ == '__main__':
    unittest.main()
