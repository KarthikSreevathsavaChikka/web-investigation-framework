import tempfile
import unittest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch

from osint.dorks import DorkGenerator
from osint.evidence_capture import (
    SERPEvidenceCapturePipeline,
    classify_page_access,
    group_evidence_positions,
    sanitize_path_component,
)
from osint.models import CollectorResult, DorkQuery, EvidenceScreenshotRecord, Observation, PageCaptureRecord, SearchResult
from osint.normalizer import DomainNormalizer, TargetNormalizationError
from osint.risk import RiskScorer
from osint.storage import OSINTRepository
from osint.documents import assess_pdf
from core.playwright_session import close_browser_session, launch_browser_session
from osint.search import AggregatingSearchProvider, BingRSSSearchProvider, DuckDuckGoSearchProvider, GoogleSearchProvider, SearchProvider
from osint.collectors.brave_search import KeylessSearchCollector
from osint.collectors.base import CollectorContext
from osint.collectors.free_discovery import CertificateTransparencyCollector, WaybackCDXCollector
from osint.docx_report import OSINTDocxReportBuilder
from osint.text_cleanup import clean_evidence_text, evidence_scope


class DomainNormalizerTests(unittest.TestCase):
    def test_normalizes_url_to_ascii_domain(self):
        target = DomainNormalizer.normalize("https://WWW.Example.com/path?q=1")
        self.assertEqual(target.domain, "www.example.com")
        self.assertEqual(target.url, "https://www.example.com")

    def test_rejects_ip_address(self):
        with self.assertRaises(TargetNormalizationError):
            DomainNormalizer.normalize("127.0.0.1")


class DorkGeneratorTests(unittest.TestCase):
    def test_generates_social_and_document_queries(self):
        target = DomainNormalizer.normalize("example.com")
        queries = DorkGenerator().generate(target)
        query_by_id = {item.query_id: item for item in queries}
        self.assertEqual(len(queries), 62)
        self.assertEqual(queries[0].query_id, "B001")
        self.assertEqual(queries[0].query, 'filetype:pdf "Example"')
        self.assertIn('"example.com" site:x.com', query_by_id["Q019"].query)
        self.assertIn("site:reddit.com", query_by_id["Q022"].query)
        self.assertEqual(query_by_id["Q033"].priority, "critical")
        self.assertIn("site:example.com filetype:pdf", query_by_id["Q032"].query)
        self.assertIn("deposit not credited", query_by_id["Q029"].evidence_keywords)
        self.assertIn("court order", query_by_id["Q041"].evidence_keywords)
        self.assertTrue(all(query.evidence_keywords for query in queries))


class RiskScorerTests(unittest.TestCase):
    def test_deduplicates_and_caps_indicators(self):
        observation = Observation(
            "test", "Applications.Direct downloads", "APPLICATION_URL", "https://example.com/app.apk",
            "https://example.com", confidence=0.9, risk_points=10,
        )
        assessment = RiskScorer.assess([observation, observation])
        self.assertEqual(assessment.score, 10)
        self.assertEqual(len(assessment.indicators), 1)


class RepositoryTests(unittest.TestCase):
    def test_persists_queries_and_deduplicated_observations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = OSINTRepository(Path(temp_dir) / "osint.db")
            target = DomainNormalizer.normalize("example.com")
            repository.create_investigation("OSINT_TEST", target)
            repository.save_queries("OSINT_TEST", DorkGenerator().generate(target))
            observation = Observation("test", "Identity", "DOMAIN", "example.com", "https://example.com")
            repository.save_collector_result("OSINT_TEST", CollectorResult("test", "COMPLETED", [observation, observation]))

            self.assertGreater(len(repository.get_queries("OSINT_TEST")), 10)
            self.assertEqual(len(repository.get_observations("OSINT_TEST")), 1)

    def test_maps_duplicate_source_to_multiple_queries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = OSINTRepository(Path(temp_dir) / "osint.db")
            target = DomainNormalizer.normalize("example.com")
            repository.create_investigation("OSINT_MAP", target)
            observations = []
            for query_id, rank in (("Q001", 2), ("Q029", 1)):
                observations.append(
                    Observation(
                        "brave_search", "Search.money_flow", "SEARCH_RESULT", "Example evidence",
                        "https://reports.example.org/item?utm_source=test", confidence=0.7,
                        metadata={
                            "query_id": query_id,
                            "query_text": "query",
                            "search_engine": "brave",
                            "rank": rank,
                            "title": "Example evidence",
                            "snippet": "deposit evidence",
                            "normalized_url": "https://reports.example.org/item",
                            "source_type": "unknown",
                        },
                    )
                )
            repository.save_collector_result("OSINT_MAP", CollectorResult("brave_search", "COMPLETED", observations))
            sources = repository.get_sources("OSINT_MAP")
            self.assertEqual(len(sources), 1)
            self.assertEqual(sources[0]["discovered_by_queries"], 2)
            self.assertEqual(sources[0]["best_rank"], 1)

    def test_prioritizes_document_query_sources_for_download(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = OSINTRepository(Path(temp_dir) / "osint.db")
            target = DomainNormalizer.normalize("example.com")
            repository.create_investigation("OSINT_DOCS", target)
            repository.save_queries("OSINT_DOCS", DorkGenerator().generate(target))
            observations = [
                Observation("search", "Search", "SEARCH_RESULT", "Web page", "https://example.net/page", metadata={"query_id": "B002", "query_text": "reviews", "search_engine": "test", "rank": 1, "title": "Example reviews", "snippet": "Example review", "normalized_url": "https://example.net/page", "source_type": "unknown"}),
                Observation("search", "Search", "SEARCH_RESULT", "PDF", "https://papers.test/example.pdf", metadata={"query_id": "B001", "query_text": "filetype:pdf Example", "search_engine": "test", "rank": 9, "title": "Example research PDF", "snippet": "Example analysis", "normalized_url": "https://papers.test/example.pdf", "source_type": "pdf_document"}),
            ]
            repository.save_collector_result("OSINT_DOCS", CollectorResult("search", "COMPLETED", observations))
            self.assertEqual(repository.get_sources("OSINT_DOCS")[0]["source_url"], "https://papers.test/example.pdf")

    def test_persists_screenshot_metadata_and_query_metrics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = OSINTRepository(Path(temp_dir) / "osint.db")
            target = DomainNormalizer.normalize("example.com")
            repository.create_investigation("OSINT_EVIDENCE", target)
            repository.save_queries("OSINT_EVIDENCE", DorkGenerator().generate(target))
            repository.save_collector_result(
                "OSINT_EVIDENCE",
                CollectorResult(
                    "brave_search", "COMPLETED", [Observation(
                        "brave_search", "Search", "SEARCH_RESULT", "Complaint",
                        "https://reviews.example.net/item?utm_source=x", metadata={
                            "query_id": "Q029", "query_text": "query", "search_engine": "brave",
                            "rank": 1, "normalized_url": "https://reviews.example.net/item",
                            "source_type": "review_site", "title": "Complaint",
                        },
                    )]
                ),
            )
            task = repository.get_evidence_tasks("OSINT_EVIDENCE", 5)[0]
            screenshot = Path(temp_dir) / "evidence.png"
            screenshot.write_bytes(b"png")
            record = PageCaptureRecord(
                source_id=task["source_id"], source_url=task["source_url"], final_url=task["source_url"],
                page_title="Complaint", http_status=200, accessibility_status="evidence_found",
                screenshots=[EvidenceScreenshotRecord(
                    "Q029", "External evidence", "External", "brave", 1,
                    ["deposit", "deposit not credited"], ["deposit not credited"],
                    "Deposit not credited", "Deposit was not credited to my wallet.",
                    "exact_phrase", str(screenshot), "abc123", 0.95,
                )],
            )
            repository.save_page_captures("OSINT_EVIDENCE", [record])
            self.assertEqual(repository.get_evidence("OSINT_EVIDENCE")[0]["query_id"], "Q029")
            metrics = {item["query_id"]: item for item in repository.get_query_metrics("OSINT_EVIDENCE")}
            self.assertEqual(metrics["Q029"]["screenshots"], 1)


class EvidenceCaptureTests(unittest.TestCase):
    def test_every_query_includes_gambling_evidence_vocabulary(self):
        queries = DorkGenerator().generate(DomainNormalizer.normalize("example.com"))
        for query in queries:
            keywords = {item.casefold() for item in query.evidence_keywords}
            self.assertTrue({"betting", "gambling", "casino", "sportsbook", "wagering"}.issubset(keywords))

    def test_groups_nearby_matches_and_sanitizes_paths(self):
        groups = group_evidence_positions([{"documentY": 20}, {"documentY": 200}, {"documentY": 900}])
        self.assertEqual([len(group) for group in groups], [2, 1])
        self.assertEqual(sanitize_path_component("../../bad source:name"), "bad_source_name")

    def test_classifies_manual_review_without_bypass(self):
        self.assertEqual(classify_page_access(403, "")[0], "manual_required")
        self.assertEqual(classify_page_access(200, "Please verify you are human")[0], "manual_required")
        self.assertEqual(classify_page_access(404, "")[0], "failed")

    @patch("osint.documents.extract_pdf_pages")
    def test_pdf_requires_target_and_classifies_relevant_pages(self, extract_pages):
        extract_pages.return_value = [
            "Parimatch payment guide. A deposit can be made using UPI.",
            "Parimatch withdrawal and wallet information.",
        ]
        target = DomainNormalizer.normalize("parimatch.com")
        target = type(target)(target.raw_input, target.domain, target.url, brand="Parimatch")
        result = assess_pdf(b"pdf", target, ["deposit", "withdrawal", "wallet"])
        self.assertTrue(result.accepted)
        self.assertEqual(result.document_type, "Payment / Deposit / Withdrawal")
        self.assertEqual(result.relevant_pages, (1, 2))

    @patch("osint.documents.extract_pdf_pages")
    def test_pdf_rejects_generic_deposit_document(self, extract_pages):
        extract_pages.return_value = ["A general definition of a bank deposit and payment."]
        target = DomainNormalizer.normalize("parimatch.com")
        result = assess_pdf(b"pdf", target, ["deposit"])
        self.assertFalse(result.accepted)

    @patch("osint.documents.extract_pdf_pages")
    def test_pdf_with_target_only_is_kept_as_a_document(self, extract_pages):
        extract_pages.return_value = ["Independent research paper referencing Parimatch in a market overview."]
        target = DomainNormalizer.normalize("parimatch.com")
        result = assess_pdf(b"pdf", target, ["withdrawal"])
        self.assertTrue(result.accepted)
        self.assertEqual(result.matched_keywords, ())
        self.assertEqual(result.relevant_pages, (1,))

    def test_playwright_highlights_fixture_and_takes_screenshot(self):
        async def exercise():
            resources = await launch_browser_session(headless=True)
            try:
                page = await resources.context.new_page()
                await page.set_content(
                    "<html><body><h1>Fun88 complaint</h1><p>Deposit of Rs 2500 was not credited to the player's wallet.</p></body></html>"
                )
                matches = await SERPEvidenceCapturePipeline.highlight_page(
                    page, ["deposit", "not credited", "wallet"]
                )
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = Path(temp_dir) / "fixture.png"
                    await page.screenshot(path=str(path))
                    self.assertGreater(path.stat().st_size, 0)
                return matches
            finally:
                await close_browser_session(resources)

        try:
            matches = asyncio.run(exercise())
        except Exception as exc:
            self.skipTest(f"Playwright browser unavailable: {exc}")
        self.assertEqual(
            {item["keyword"].casefold() for item in matches},
            {"deposit", "not credited", "wallet"},
        )


class KeylessSearchProviderTests(unittest.TestCase):
    def test_combined_collector_records_each_provider_and_partial_failure(self):
        class StaticProvider(SearchProvider):
            capabilities = BingRSSSearchProvider.capabilities

            def __init__(self, name, *, fail=False):
                self.name = name
                self.fail = fail

            @property
            def available(self):
                return True

            def search(self, query, *, query_id, count):
                if self.fail:
                    raise RuntimeError("temporarily unavailable")
                return [SearchResult(
                    query_id,
                    query,
                    self.name,
                    1,
                    "Example official login",
                    "https://example.com/login",
                    "Example account login",
                )]

        provider = AggregatingSearchProvider([
            StaticProvider("bing_rss"),
            StaticProvider("duckduckgo", fail=True),
        ], name="keyless_aggregated")
        collector = KeylessSearchCollector(provider)
        query = DorkQuery("Q001", "authentication", "Login", "high", '"example" login', "Login pages")

        observations = collector.collect(
            DomainNormalizer.normalize("example.com"),
            CollectorContext([query], search_query_budget=1, results_per_query=5),
        )

        executions = [item for item in observations if item.entity_type == "QUERY_EXECUTION"]
        self.assertEqual(
            {(item.metadata["provider"], item.metadata["status"]) for item in executions},
            {("bing_rss", "completed"), ("duckduckgo", "failed")},
        )
        self.assertTrue(any(item.entity_type == "SEARCH_PROVIDER_ERROR" for item in observations))
        self.assertTrue(any(item.entity_type == "SEARCH_RESULT" for item in observations))

    @patch("osint.search.requests.get")
    def test_parses_google_brand_results(self, get):
        response = Mock()
        response.url = "https://www.google.com/search?q=parimatch"
        response.text = """
        <html><body><div><a href="https://www.scribd.com/document/123"><h3>Parimatch Deposit Guide PDF</h3></a>
        <div class="VwiC3b">Parimatch deposit and withdrawal information.</div></div></body></html>
        """
        response.raise_for_status.return_value = None
        get.return_value = response
        provider = GoogleSearchProvider()
        provider.cache_ttl = 0
        results = provider.search('filetype:pdf "Parimatch"', query_id="B001", count=10)
        self.assertEqual(results[0].url, "https://www.scribd.com/document/123")
        self.assertEqual(results[0].search_engine, "google")

    @patch("osint.search.requests.get")
    def test_google_empty_page_is_not_reported_as_success(self, get):
        response = Mock()
        response.url = "https://www.google.com/search?q=parimatch"
        response.text = "<html><head><title>Before you continue</title></head><body>Consent</body></html>"
        response.raise_for_status.return_value = None
        get.return_value = response
        provider = GoogleSearchProvider()
        provider.api_key = ""
        provider.cse_id = ""
        provider.cache_ttl = 0
        with self.assertRaisesRegex(RuntimeError, "no parseable organic results"):
            provider.search('filetype:pdf "Parimatch"', query_id="B001", count=10)

    @patch("osint.search.requests.get")
    def test_google_429_is_reported_without_http_traceback(self, get):
        response = Mock()
        response.status_code = 429
        response.url = "https://www.google.com/sorry/index"
        response.text = "Too Many Requests"
        get.return_value = response
        provider = GoogleSearchProvider()
        provider.api_key = ""
        provider.cse_id = ""
        provider.cache_ttl = 0
        with self.assertRaisesRegex(RuntimeError, "rate-limited"):
            provider.search('"Tashanwin"', query_id="RESOLVE_01", count=10)
        response.raise_for_status.assert_not_called()
    @patch("osint.search.requests.get")
    def test_parses_duckduckgo_html_results_and_redirect_url(self, get):
        response = Mock()
        response.text = """
        <div class="result">
          <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Freviews.example%2Fcomplaint">Complaint report</a>
          <a class="result__snippet">Deposit was not credited.</a>
        </div>
        """
        response.raise_for_status.return_value = None
        get.return_value = response
        provider = DuckDuckGoSearchProvider()
        provider.cache_ttl = 0
        results = provider.search("example complaint", query_id="Q029", count=10)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].url, "https://reviews.example/complaint")
        self.assertEqual(results[0].search_engine, "duckduckgo")

    @patch("osint.search.requests.get")
    def test_parses_bing_rss_results(self, get):
        response = Mock()
        response.content = b"""<?xml version='1.0'?><rss><channel><item>
          <title>Complaint report</title><link>https://reviews.example/complaint</link>
          <description>Deposit was not credited.</description>
        </item></channel></rss>"""
        response.raise_for_status.return_value = None
        get.return_value = response
        provider = BingRSSSearchProvider()
        provider.cache_ttl = 0
        results = provider.search("example complaint", query_id="Q029", count=10)
        self.assertEqual(results[0].url, "https://reviews.example/complaint")
        self.assertEqual(results[0].search_engine, "bing_rss")

    def test_social_queries_produce_manual_review_links(self):
        target = DomainNormalizer.normalize("example.com")
        query = DorkGenerator().generate(target)[0]
        query = next(item for item in DorkGenerator().generate(target) if item.category == "support_social")
        links = KeylessSearchCollector._manual_social_links(target, query)
        self.assertEqual({item.value for item in links}, {"X/Twitter", "Reddit", "Instagram", "Facebook", "Telegram"})
        self.assertTrue(all(item.metadata["status"] == "manual_required" for item in links))


class FreeDiscoveryTests(unittest.TestCase):
    @patch("osint.collectors.free_discovery.requests.get")
    def test_certificate_transparency_returns_leads_only(self, get):
        response = Mock()
        response.json.return_value = [{"name_value": "www.examplebet.com\nmirror.examplebet.com"}]
        response.raise_for_status.return_value = None
        get.return_value = response
        result = CertificateTransparencyCollector().collect(DomainNormalizer.normalize("examplebet.com"), CollectorContext([]))
        self.assertTrue(result)
        self.assertTrue(all(item.entity_type == "CANDIDATE_DOMAIN" and item.metadata["lead_only"] for item in result))

    @patch("osint.collectors.free_discovery.requests.get")
    def test_wayback_urls_must_pass_the_serp_gate(self, get):
        response = Mock()
        response.json.return_value = [["timestamp", "original"], ["20250101000000", "https://examplebet.com/payments"]]
        response.raise_for_status.return_value = None
        get.return_value = response
        result = WaybackCDXCollector().collect(DomainNormalizer.normalize("examplebet.com"), CollectorContext([], results_per_query=5))
        self.assertEqual(result[0].entity_type, "SEARCH_RESULT")
        self.assertEqual(result[0].metadata["search_engine"], "wayback_cdx")

    def test_docx_export_is_a_valid_office_document(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = OSINTRepository(Path(temp_dir) / "osint.db")
            repository.create_investigation("OSINT_DOCX", DomainNormalizer.normalize("example.com"))
            self.assertTrue(OSINTDocxReportBuilder(repository).build("OSINT_DOCX").startswith(b"PK"))

    def test_report_does_not_call_external_brand_evidence_exact_domain(self):
        self.assertEqual(
            evidence_scope(
                "https://pari-match.pro.in/article",
                "https://pari-match.pro.in/article",
                "pari-pro.in",
            ),
            "External brand-related public page",
        )
        self.assertEqual(
            evidence_scope("https://pari-pro.in/", "https://parimatchs123.com/", "pari-pro.in"),
            "Target-domain URL redirected to an external page",
        )

    def test_evidence_text_is_deduplicated_and_not_cut_mid_word(self):
        repeated = (
            "Parimatch supports deposits. Withdrawals are processed quickly.\n\n"
            "Parimatch supports deposits. Withdrawals are processed quickly."
        )
        self.assertEqual(
            clean_evidence_text(repeated),
            "Parimatch supports deposits. Withdrawals are processed quickly.",
        )
        shortened = clean_evidence_text("A complete sentence. " + "word " * 50, limit=45)
        self.assertFalse(shortened.endswith(" wor…"))


if __name__ == "__main__":
    unittest.main()
