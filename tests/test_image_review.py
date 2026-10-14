import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from PIL import Image

from osint.image_review import ScreenshotSummarizer, screenshot_tasks, validate_image_summary
from osint.models import CollectorResult, Observation
from osint.normalizer import DomainNormalizer
from osint.storage import OSINTRepository


class ScreenshotSummaryTests(unittest.TestCase):
    def test_default_capacity_covers_a_normal_investigation(self):
        with patch.dict(os.environ, {}, clear=True):
            reviewer = ScreenshotSummarizer()
        self.assertEqual(reviewer.budget, 50)
        self.assertEqual(reviewer.seconds, 600)

    def test_repository_returns_stored_screenshot_summary_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = OSINTRepository(Path(directory) / "test.db")
            target = DomainNormalizer.normalize("example.com")
            repository.create_investigation("IMAGE_SUMMARY", target)
            repository.save_collector_result("IMAGE_SUMMARY", CollectorResult(
                "llm_screenshot_summary", "COMPLETED", [Observation(
                    "llm_screenshot_summary", "Advisory visual summary", "LLM_SCREENSHOT_SUMMARY",
                    "hash", target.url, metadata={"screenshot_path": "/evidence/page.png", "summary": "Example page"},
                )],
            ))
            self.assertEqual(repository.get_screenshot_summaries("IMAGE_SUMMARY")[0]["screenshot_path"], "/evidence/page.png")

    def test_validates_bounded_structured_summary(self):
        value = {"summary": "The image shows the Example login page.", "visible_text": "Example Log in", "relevance": "relevant"}
        self.assertEqual(validate_image_summary(value), value)
        for invalid in ({**value, "extra": "x"}, {**value, "relevance": "confirmed"}, {**value, "summary": ""}):
            with self.assertRaises(ValueError):
                validate_image_summary(invalid)

    def test_collects_and_deduplicates_all_screenshot_types(self):
        repo = Mock()
        repo.get_evidence.return_value = [{"screenshot_path": "/a.png", "sha256": "a", "source_url": "https://example.com", "context_text": "page"}]
        repo.get_social_findings.return_value = [{"screenshot_paths": ["/a.png", "/b.png"], "post_url": "https://social.example/p", "post_text": "post"}]
        repo.get_documents.return_value = [{"source_url": "https://example.com/a.pdf", "evidence_context": "document", "page_screenshots": [{"path": "/c.png", "sha256": "c"}]}]
        self.assertEqual([item["path"] for item in screenshot_tasks(repo, "TEST")], ["/a.png", "/b.png", "/c.png"])

    @patch("osint.image_review.requests.post")
    def test_sends_image_and_preserves_provenance(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"message": {"content": json.dumps({
            "summary": "The screenshot shows the Example homepage.", "visible_text": "Example", "relevance": "relevant"
        })}}]}
        post.return_value = response
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"OSINT_LLM_IMAGE_REVIEW_BUDGET": "1"}):
            path = Path(directory) / "shot.png"
            Image.new("RGB", (20, 20), "white").save(path)
            result = ScreenshotSummarizer().run(DomainNormalizer.normalize("example.com"), [{
                "path": str(path), "sha256": None, "source_url": "https://example.com", "kind": "web_evidence", "context": "Example homepage"
            }])
        review = result.observations[0].metadata
        message = post.call_args.kwargs["json"]["messages"][1]["content"]
        self.assertTrue(message[1]["image_url"]["url"].startswith("data:image/jpeg;base64,"))
        self.assertEqual(len(review["sha256"]), 64)
        self.assertEqual(review["review_status"], "reviewed")
        self.assertEqual(review["screenshot_path"], str(path))
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
