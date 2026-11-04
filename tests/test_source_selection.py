import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import requests

from osint.collectors.results import PublicSearchResultCollector
from osint.dorks import DorkGenerator
from osint.evidence_capture import SERPEvidenceCapturePipeline
from osint.models import CollectorResult, Observation
from osint.normalizer import DomainNormalizer, TargetNormalizationError, target_for_domain
from osint.storage import OSINTRepository
from osint.url_tools import classify_response_content, classify_source_url, is_content_page_url


class SourceClassificationTests(unittest.TestCase):
    def test_extensionless_assets_are_excluded_but_document_viewers_remain(self):
        for url in (
            "https://example.com/cms-assets/129ad674-e5fe-48c1-a9ca-6ae56e48fca0",
            "https://example.com/resource?format=SVG&width=1600",
            "https://example.com/resource?fm=webp",
            "https://example.com/a%2EJS?v=1",
            "https://example.com/get?format=image%2Fpng",
        ):
            self.assertFalse(is_content_page_url(url), url)
        for url in (
            "https://example.com/cms-assets/reports",
            "https://example.com/cms-assets/report.pdf",
            "https://example.com/view?format=html&id=123",
            "https://example.com/download?format=pdf",
            "https://example.com/assets/company-history",
            "https://example.com/view?width=300&id=123",
        ):
            self.assertTrue(is_content_page_url(url), url)

    def test_response_type_overrides_misleading_url_and_preserves_documents(self):
        self.assertEqual(classify_response_content("https://example.com/api/42", "image/png").kind, "media")
        self.assertEqual(classify_response_content("https://example.com/report.pdf", "text/html; charset=utf-8").kind, "page")
        self.assertEqual(classify_response_content("https://example.com/file", "application/octet-stream", b"%PDF-1.7").kind, "document")
        self.assertEqual(classify_response_content("https://example.com/file", "application/json").kind, "structured_data")
        self.assertEqual(classify_response_content("https://example.com/file", "application/octet-stream").kind, "binary")
        self.assertEqual(classify_response_content("https://example.com/download", "application/msword").kind, "document")

    def test_assets_do_not_consume_capture_budget_and_are_still_stored(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = OSINTRepository(Path(directory) / "selection.db")
            target = DomainNormalizer.normalize("example.com/en/?lang=en&source=Official")
            queries = DorkGenerator().generate(target)
            repository.create_investigation("SELECTION", target)
            repository.save_queries("SELECTION", queries)
            observations = []
            paths = ["resource?format=svg", "cms-assets/129ad674-e5fe-48c1-a9ca-6ae56e48fca0", "reviews"]
            for rank, path in enumerate(paths, 1):
                url = f"https://example.com/{path}"
                observations.append(Observation("search", "Search", "SEARCH_RESULT", path, url, metadata={
                    "query_id": queries[0].query_id, "query_text": queries[0].query, "search_engine": "test",
                    "rank": rank, "normalized_url": url, "source_type": "webpage",
                }))
            repository.save_collector_result("SELECTION", CollectorResult("search", "COMPLETED", observations))
            repository.ensure_first_party_source("SELECTION", target, queries)
            tasks = repository.get_evidence_tasks("SELECTION", 2)
            self.assertEqual(len(tasks), 2)
            self.assertTrue(tasks[0]["first_party_seed"])
            self.assertEqual(tasks[0]["source_url"], target.url)
            self.assertTrue(tasks[1]["source_url"].endswith("/reviews"))
            self.assertEqual(len(repository.get_sources("SELECTION")), 4)


class TargetURLPreservationTests(unittest.TestCase):
    def test_primary_domain_keeps_supplied_subdomain_path_case_and_functional_query(self):
        original = "https://WWW.Example.com/EN/Profile/?source=Official&ref=ABc%2F42"
        expected = "https://www.example.com/EN/Profile/?source=Official&ref=ABc%2F42"
        self.assertEqual(target_for_domain(original, "example.com"), expected)
        self.assertEqual(target_for_domain(original, "www.example.com"), expected)
        self.assertEqual(target_for_domain(original, "example.net"), "example.net")
        self.assertEqual(target_for_domain(original, "different.example.com"), "different.example.com")
        self.assertEqual(target_for_domain("Example Brand", "example.com"), "example.com")

    def test_preserves_explicit_transport_path_and_query(self):
        target = DomainNormalizer.normalize("http://WWW.Example.com:8080/en/?lang=en&x=a%2Fb#section")
        self.assertEqual(target.domain, "www.example.com")
        self.assertEqual(target.url, "http://www.example.com:8080/en/?lang=en&x=a%2Fb")
        self.assertEqual(DomainNormalizer.normalize("example.com/en/").url, "https://example.com/en/")

    def test_encodes_international_url_without_double_encoding(self):
        target = DomainNormalizer.normalize("https://bücher.de/über/?q=über%20uns")
        self.assertEqual(target.url, "https://xn--bcher-kva.de/%C3%BCber/?q=%C3%BCber%20uns")

    def test_rejects_unsafe_schemes_credentials_and_invalid_hosts(self):
        for url in ("file://example.com/a", "https://user:password@example.com/en/", "http://127.0.0.1/",
                    "https://example.com:abc/", "https://exa_mple.com/", "https://example.com/a\nb"):
            with self.subTest(url=url), self.assertRaises(TargetNormalizationError):
                DomainNormalizer.normalize(url)

    @patch("osint.normalizer.socket.getaddrinfo")
    def test_mixed_public_private_dns_is_still_rejected(self, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443)),
                                    (None, None, None, None, ("127.0.0.1", 443))]
        self.assertEqual(DomainNormalizer.public_addresses("example.com"), [])


class ResourceCollectionTests(unittest.TestCase):
    @staticmethod
    def response(url, content_type, body):
        response = requests.Response()
        response.url = url
        response.status_code = 200
        response.headers["Content-Type"] = content_type
        response._content = body
        return response

    def collect(self, sources):
        with patch("osint.collectors.results.time.sleep"):
            return PublicSearchResultCollector().collect(DomainNormalizer.normalize("example.com"), sources, 3, "SELECTION")

    @patch("osint.collectors.results.get_public_url")
    def test_known_media_reference_is_retained_without_fetch(self, get):
        result = self.collect([{"source_url": "https://example.com/image?format=webp", "title": "Brand logo"}])
        get.assert_not_called()
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.observations[0].entity_type, "MEDIA_REFERENCE")
        self.assertEqual(result.observations[0].metadata["classification_basis"], "url_hint")

    @patch("osint.collectors.results.BeautifulSoup")
    @patch("osint.collectors.results.get_public_url")
    def test_extensionless_image_is_not_parsed_as_html_or_reported_as_failure(self, get, soup):
        get.return_value = self.response("https://example.com/object/42", "image/png", b"\x89PNG\r\n")
        result = self.collect([{"source_url": "https://example.com/object/42"}])
        soup.assert_not_called()
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.observations[0].entity_type, "MEDIA_REFERENCE")
        self.assertEqual(result.observations[0].metadata["media_type"], "image/png")

    @patch("osint.collectors.results.assess_pdf")
    @patch("osint.collectors.results.get_public_url")
    def test_html_pdf_viewer_is_processed_as_page(self, get, assess_pdf):
        get.return_value = self.response("https://example.com/report.pdf", "text/html", b"<html><title>Example report</title><body>example.com report.</body></html>")
        result = self.collect([{"source_url": "https://example.com/report.pdf", "source_type": "pdf_document"}])
        assess_pdf.assert_not_called()
        self.assertTrue(any(item.entity_type == "PUBLIC_PAGE_METADATA" for item in result.observations))

    @patch("osint.collectors.results.assess_pdf")
    @patch("osint.collectors.results.get_public_url")
    def test_extensionless_pdf_download_uses_document_extraction(self, get, assess_pdf):
        get.return_value = self.response("https://example.com/download?id=12", "application/octet-stream", b"%PDF-1.7 test")
        assess_pdf.return_value = Mock(accepted=False, reason="No target reference")
        result = self.collect([{"source_url": "https://example.com/download?id=12"}])
        assess_pdf.assert_called_once()
        self.assertEqual(result.observations[0].entity_type, "DOCUMENT_REJECTED")

    @patch("osint.collectors.results.get_public_url")
    def test_unsupported_document_download_reports_manual_review(self, get):
        get.return_value = self.response("https://example.com/download", "application/msword", b"legacy document")
        result = self.collect([{"source_url": "https://example.com/download"}])
        self.assertEqual(result.status, "PARTIAL")
        self.assertEqual(result.observations[0].entity_type, "DOCUMENT_REJECTED")
        self.assertEqual(result.observations[0].value, "manual_required")


class ResourceCaptureTests(unittest.TestCase):
    def test_known_asset_never_opens_browser_page(self):
        async def run():
            pipeline = SERPEvidenceCapturePipeline(Path("/tmp"))
            context = Mock(new_page=AsyncMock())
            with patch("osint.evidence_capture.DomainNormalizer.public_addresses") as addresses:
                result = await pipeline._capture_source(context, None, "SELECTION", "example.com", {
                    "source_id": 1, "source_url": "https://example.com/resource?format=svg",
                })
            context.new_page.assert_not_awaited()
            addresses.assert_not_called()
            self.assertEqual(result.accessibility_status, "skipped_non_content")
        asyncio.run(run())

    def test_response_media_type_skips_body_capture_but_http_blocks_remain_failures(self):
        async def run(status):
            pipeline = SERPEvidenceCapturePipeline(Path("/tmp"))
            page = Mock(url="https://example.com/object/42", title=AsyncMock(), close=AsyncMock())
            context = Mock(new_page=AsyncMock(return_value=page))
            pipeline._navigate_page = AsyncMock(return_value=Mock(status=status, headers={"content-type": "image/png"}))
            pipeline._wait_for_visual_readiness = AsyncMock()
            with patch("osint.evidence_capture.DomainNormalizer.public_addresses", return_value=["93.184.216.34"]):
                result = await pipeline._capture_source(context, None, "SELECTION", "example.com", {
                    "source_id": 1, "source_url": "https://example.com/object/42", "queries": [],
                })
            pipeline._wait_for_visual_readiness.assert_not_awaited()
            page.title.assert_not_awaited()
            page.locator.assert_not_called()
            page.close.assert_awaited_once()
            return result
        self.assertEqual(asyncio.run(run(200)).accessibility_status, "skipped_non_content")
        self.assertEqual(asyncio.run(run(403)).accessibility_status, "manual_required")


if __name__ == "__main__":
    unittest.main()
