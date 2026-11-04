import unittest
import tempfile
from unittest.mock import Mock

import requests

from osint.domain_intelligence import DomainIntelligenceService, SimilarwebTrafficProvider, http_status_meaning
from osint.report import OSINTReportBuilder
from osint.storage import OSINTRepository
from osint.models import NormalizedTarget


class Response:
    def __init__(self, code=200, location=None, text="", url=""):
        self.status_code, self.headers, self.text, self.url = code, ({"Location": location} if location else {}), text, url
        self.history = []
    @property
    def is_redirect(self): return self.status_code in {301, 302, 303, 307, 308}
    def close(self): pass


class DomainIntelligenceTests(unittest.TestCase):
    def test_http_status_meanings_are_analyst_friendly(self):
        self.assertEqual(
            http_status_meaning("403"),
            "Server exists but blocks automated access, your location, or this user.",
        )
        self.assertEqual(http_status_meaning("404"), "Server exists, but this page was not found.")
        self.assertIn("redirecting", http_status_meaning("200", "Active – Redirected"))

    def service(self, responses, traffic=None):
        def request(*args, **kwargs):
            value = responses.pop(0)
            if isinstance(value, Exception): raise value
            return value
        return DomainIntelligenceService(request=request, retries=0, public_host=lambda host: host != "private.test", traffic_provider=traffic or Mock(lookup=lambda domain: {"traffic_source": "Unavailable"}))

    def test_active_200(self):
        check = self.service([Response(200)]).check("example.test")
        self.assertEqual((check.domain_status, check.http_status), ("Active", "200"))

    def test_redirect_and_private_redirect_blocked(self):
        check = self.service([Response(301, "https://next.test/"), Response(200)]).check("example.test")
        self.assertEqual(check.detailed_status, "Active – Redirected")
        blocked = self.service([Response(302, "http://private.test/")]).check("example.test")
        self.assertEqual(blocked.detailed_status, "Unknown – Redirect blocked")

    def test_restricted_timeout_and_http_fallback(self):
        restricted = self.service([Response(403)]).check("example.test")
        self.assertEqual(restricted.detailed_status, "Active – Access Restricted")
        timeout = self.service([requests.Timeout(), requests.Timeout()]).check("example.test")
        self.assertEqual(timeout.detailed_status, "Unknown – Timeout")
        fallback = self.service([requests.ConnectionError("bad tls"), Response(200)]).check("example.test")
        self.assertEqual(fallback.final_url, "http://example.test/")

    def test_deduplicates_and_keeps_batch_running(self):
        service = self.service([Response(200), RuntimeError("bad")])
        checks = service.check_many(["one.test", "one.test", "two.test"])
        self.assertEqual(len(checks), 2)
        self.assertTrue(any(item.domain == "two.test" for item in checks))

    def test_traffic_success_and_no_data(self):
        provider = SimilarwebTrafficProvider("key", request=lambda *a, **k: type("R", (), {"status_code": 200, "json": lambda s: {"visits": [{"visits": 100, "date": "2026-01"}]}})())
        import os
        old = os.environ.get("TRAFFIC_PROVIDER"); os.environ["TRAFFIC_PROVIDER"] = "similarweb"
        try:
            data = provider.lookup("example.test")
            self.assertEqual((data["monthly_visits"], data["yearly_visits"], data["yearly_visits_kind"]), (100, 1200, "Projected"))
        finally:
            if old is None: os.environ.pop("TRAFFIC_PROVIDER")
            else: os.environ["TRAFFIC_PROVIDER"] = old

    def test_traffic_rate_limit_and_missing_credentials(self):
        import os
        old = os.environ.get("TRAFFIC_PROVIDER"); os.environ["TRAFFIC_PROVIDER"] = "similarweb"
        try:
            limited = SimilarwebTrafficProvider("key", request=lambda *a, **k: type("R", (), {"status_code": 429})()).lookup("x.test")
            self.assertIn("rate limited", limited["error"])
            self.assertEqual(SimilarwebTrafficProvider("").lookup("x.test")["traffic_source"], "Unavailable")
        finally:
            if old is None: os.environ.pop("TRAFFIC_PROVIDER")
            else: os.environ["TRAFFIC_PROVIDER"] = old


class DomainExportTests(unittest.TestCase):
    def test_json_csv_and_html_include_domain_fields(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db")
        repo = OSINTRepository(tmp.name)
        repo.create_investigation("test", NormalizedTarget("example.test", "example.test", "https://example.test/"))
        # Export builders expose standardized domain columns even with no investigation data.
        builder = OSINTReportBuilder(repo)
        self.assertIn("monthly_visits", builder.build_domain_csv("test"))
        self.assertIn('"domains"', builder.build_json("test"))
        self.assertIn("Monthly Visits", builder.build_html("test"))
