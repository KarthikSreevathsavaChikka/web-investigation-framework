import tempfile
import unittest
from pathlib import Path

from osint.models import CollectorResult, Observation, PageCaptureRecord, EvidenceScreenshotRecord
from osint.normalizer import DomainNormalizer
from osint.storage import OSINTRepository
from osint.text_cleanup import social_screenshot_context


class FindingScreenshotTests(unittest.TestCase):
    def test_public_capture_attaches_only_to_matching_finding_and_retains_snippet_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / "test.db")
            repo.create_investigation("TEST", DomainNormalizer.normalize("example.com"))
            url = "https://reddit.com/r/test/comments/123/example"
            repo.save_collector_result("TEST", CollectorResult("search", "COMPLETED", [
                Observation("search", "Search", "SEARCH_RESULT", "Example", url,
                            metadata={"normalized_url": url, "source_type": "social", "rank": 1, "query_id": "Q1"}),
                *[Observation("search", "Social", "AUTOMATED_SOCIAL_FINDING", "Example", post,
                              metadata={"platform": "Reddit", "post_text": "Search snippet"})
                  for post in [url + "?utm_source=search", url + "2"]],
            ]))
            task = repo.get_evidence_tasks("TEST", 5)[0]
            shot = EvidenceScreenshotRecord(
                "Q1", "Example", "Social", "test", 1, [], [], "Example", "Visible page text",
                "page_baseline", "/evidence/test.png", "hash", 0.7,
            )
            repo.save_page_captures("TEST", [PageCaptureRecord(
                source_id=task["source_id"], source_url=url, final_url=url,
                accessibility_status="baseline_captured", screenshots=[shot, shot],
            )])
            findings = {f["post_url"]: f for f in repo.get_social_findings("TEST")}
            finding = findings[url + "?utm_source=search"]
            self.assertEqual(finding["screenshot_paths"], ["/evidence/test.png"])
            self.assertEqual(finding["content_scope"], "search_snippet")
            self.assertEqual(finding["capture_status"], "page_captured")
            self.assertEqual(social_screenshot_context(finding, "/evidence/test.png")["text"], "Visible page text")
            self.assertEqual(findings[url + "2"]["screenshot_paths"], [])
            repo.save_page_captures("TEST", [PageCaptureRecord(
                source_id=task["source_id"], source_url=url,
                accessibility_status="manual_required", failure_reason="Login required",
            )])
            finding = next(f for f in repo.get_social_findings("TEST") if f["post_url"] == url + "?utm_source=search")
            self.assertEqual(finding["screenshot_paths"], [])
            self.assertEqual(finding["capture_reason"], "Login required")
