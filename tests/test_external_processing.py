import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from docx import Document

from services.external_processing import (
    _build_combined_report,
    external_report_filename,
    send_external_callback,
)


class ExternalCallbackTests(unittest.TestCase):
    def test_combined_report_contains_routing_ids_and_every_domain_investigation(self):
        payload = {
            "external_job_id": "EXT-42",
            "complaint_id": "CMP-7",
            "target_id": "TGT-9",
            "target": "https://primary.example/path",
        }
        resolution = SimpleNamespace(
            resolved_brand="Example",
            candidates=[
                SimpleNamespace(domain="primary.example"),
                SimpleNamespace(domain="related.example"),
            ],
        )
        repository = Mock()
        repository.get_evidence.side_effect = [[], []]
        repository.get_documents.side_effect = [[], []]

        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"EXTERNAL_REPORT_DIR": directory}), \
             patch("services.external_processing.OSINTDocxReportBuilder") as builder_class:
            def append_section(document, investigation_id, *, heading_level):
                document.add_heading(f"Web Scraping — {investigation_id}", level=heading_level)

            builder_class.return_value.append.side_effect = append_section
            report_path = _build_combined_report(
                payload,
                resolution,
                ["OSINT_PRIMARY", "OSINT_RELATED"],
                None,
                repository,
            )
            document = Document(report_path)

        text = "\n".join(paragraph.text for paragraph in document.paragraphs)
        table_text = "\n".join(
            cell.text for table in document.tables for row in table.rows for cell in row.cells
        )
        self.assertIn("EXT-42", table_text)
        self.assertIn("CMP-7", table_text)
        self.assertIn("TGT-9", table_text)
        self.assertIn("primary.example", text)
        self.assertIn("related.example", text)
        self.assertIn("Web Scraping — OSINT_PRIMARY", text)
        self.assertIn("Web Scraping — OSINT_RELATED", text)
        self.assertEqual(builder_class.return_value.append.call_count, 2)

    def test_report_filename_uses_normalized_target_and_generation_date(self):
        self.assertEqual(
            external_report_filename(
                "https://WWW.Example.com/path",
                generated_at=datetime(2026, 9, 7, tzinfo=timezone.utc),
            ),
            "WebScraping-www.example.com-07-Sep-2026.docx",
        )

    def test_success_callback_uploads_one_combined_docx_with_routing_fields(self):
        response = Mock()
        response.raise_for_status.return_value = None
        payload = {
            "external_job_id": "EXT-42",
            "complaint_id": "CMP-7",
            "target_id": "TGT-9",
            "target": "fairwin247.co",
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "combined.docx"
            report.write_bytes(b"PK-test")
            with patch.dict(os.environ, {"EXTERNAL_CALLBACK_URL": "https://callback.example/endpoint"}), \
                 patch("services.external_processing.requests.post", return_value=response) as post:
                send_external_callback(
                    payload,
                    "COMPLETED",
                    result={"target_url": "https://fairwin247.co", "report_path": str(report)},
                )

        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["data"]["job_id"], "EXT-42")
        self.assertEqual(kwargs["data"]["complaint_id"], "CMP-7")
        self.assertEqual(kwargs["data"]["target_id"], "TGT-9")
        self.assertEqual(kwargs["data"]["status"], "COMPLETED")
        self.assertEqual(kwargs["data"]["url"], "https://fairwin247.co")
        self.assertIn("file", kwargs["files"])

    def test_failure_callback_does_not_attach_a_report(self):
        response = Mock()
        response.raise_for_status.return_value = None
        payload = {
            "external_job_id": "EXT-42",
            "complaint_id": "CMP-7",
            "target_id": "TGT-9",
            "target": "fairwin",
        }
        with patch.dict(os.environ, {"EXTERNAL_CALLBACK_URL": "https://callback.example/endpoint"}), \
             patch("services.external_processing.requests.post", return_value=response) as post:
            send_external_callback(payload, "FAILED", error="resolution failed")

        self.assertEqual(post.call_args.kwargs["data"]["status"], "FAILED")
        self.assertEqual(post.call_args.kwargs["data"]["error"], "resolution failed")
        self.assertNotIn("files", post.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
