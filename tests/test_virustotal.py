import tempfile
import unittest
from pathlib import Path

from docx import Document

from virustotal.client import VirusTotalClient, VirusTotalError, classify_target, expand_stored_report
from virustotal.report import build_batch_docx, build_docx
from virustotal.storage import VirusTotalRepository
from ui.virustotal_workspace import _echarts_relationship_data, _relationship_graph_data


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.request = None

    def get(self, url, **kwargs):
        self.request = (url, kwargs)
        return self.response


class VirusTotalTests(unittest.TestCase):
    def sample_payload(self):
        return {"data": {"id": "example.com", "type": "domain", "attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 10},
            "last_analysis_results": {
                "Engine A": {"engine_name": "Engine A", "category": "malicious", "result": "phishing"},
                "Engine B": {"engine_name": "Engine B", "category": "harmless", "result": "clean"},
            },
            "reputation": -4, "registrar": "Example Registrar", "tags": ["test"],
            "creation_date": 1700000000,
            "last_dns_records": [{"type": "A", "value": "192.0.2.10", "ttl": 300}],
            "last_https_certificate": {
                "subject": {"CN": "example.com"}, "issuer": {"CN": "Test CA"},
                "serial_number": "01", "validity": {"not_before": "2026-01-01", "not_after": "2027-01-01"},
            },
            "total_votes": {"harmless": 3, "malicious": 1},
            "whois": "Registrar: Example Registrar",
        }, "relationships": {
            "subdomains": {"data": [{"id": "www.example.com", "type": "domain"}], "meta": {"count": 1}},
            "resolutions": {"data": [{"id": "192.0.2.10example.com", "type": "resolution", "attributes": {"ip_address": "192.0.2.10"}}], "meta": {"count": 1}},
        }}}

    def test_classifies_domain_url_ip_and_hash(self):
        self.assertEqual(classify_target("example.com")[:2], ("domain", "example.com"))
        self.assertEqual(classify_target("https://example.com/path")[:2], ("url", "https://example.com/path"))
        self.assertEqual(classify_target("8.8.8.8")[:2], ("ip_address", "8.8.8.8"))
        self.assertEqual(classify_target("a" * 64)[:2], ("file", "a" * 64))

    def test_client_normalizes_report_and_never_places_key_in_url(self):
        session = FakeSession(FakeResponse(payload=self.sample_payload()))
        report = VirusTotalClient("secret-key", session=session).lookup("example.com")
        self.assertEqual(report["analysis_stats"]["malicious"], 2)
        self.assertEqual(report["detections"][0]["engine"], "Engine A")
        self.assertEqual(report["dns_records"][0]["value"], "192.0.2.10")
        self.assertEqual(report["relationships"]["subdomains"]["items"][0]["id"], "www.example.com")
        url, kwargs = session.request
        self.assertNotIn("secret-key", url)
        self.assertEqual(kwargs["headers"]["x-apikey"], "secret-key")

    def test_client_reports_rate_limit_safely(self):
        with self.assertRaisesRegex(VirusTotalError, "rate limit"):
            VirusTotalClient("key", session=FakeSession(FakeResponse(429))).lookup("example.com")

    def test_backfills_new_fields_from_an_existing_raw_report(self):
        legacy = {
            "target": "example.com", "target_type": "domain", "object_id": "example.com",
            "analysis_stats": {"malicious": 2}, "raw_response": self.sample_payload(),
        }
        expanded = expand_stored_report(legacy)
        self.assertEqual(expanded["registrar"], "Example Registrar")
        self.assertEqual(expanded["https_certificate"]["issuer"]["CN"], "Test CA")

    def test_builds_relationship_summary_graph_from_stored_data(self):
        report = VirusTotalClient(
            "key", session=FakeSession(FakeResponse(payload=self.sample_payload()))
        ).lookup("example.com")
        nodes, edges = _relationship_graph_data(report)
        self.assertEqual(nodes[0]["label"], "example.com")
        self.assertEqual(nodes[1]["label"], "1 subdomain(s)")
        self.assertEqual(nodes[2]["label"], "1 resolution(s)")
        self.assertEqual(len(edges), 2)

        graph = _echarts_relationship_data(report)
        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertIn("target", node_ids)
        self.assertIn("group:subdomains", node_ids)
        self.assertIn("group:resolutions", node_ids)
        self.assertIn("certificate", node_ids)
        self.assertIn("registration", node_ids)
        self.assertGreaterEqual(len(graph["links"]), 6)

    def test_persists_report_and_builds_docx(self):
        session = FakeSession(FakeResponse(payload=self.sample_payload()))
        report = VirusTotalClient("key", session=session).lookup("example.com")
        with tempfile.TemporaryDirectory() as directory:
            repository = VirusTotalRepository(Path(directory) / "vt.db")
            report_id = repository.save(report)
            stored = repository.get(report_id)
            self.assertEqual(stored["target"], "example.com")
            self.assertEqual(len(repository.list()), 1)
            content = build_docx(stored)
            path = Path(directory) / "report.docx"
            path.write_bytes(content)
            document = Document(path)
            self.assertIn("VirusTotal intelligence report", "\n".join(p.text for p in document.paragraphs))

    def test_persists_multiple_domains_as_one_batch_and_builds_one_docx(self):
        report = VirusTotalClient("key", session=FakeSession(FakeResponse(payload=self.sample_payload()))).lookup("example.com")
        results = [
            {"domain": "example.com", "status": "COMPLETED", "report": report, "error": None},
            {"domain": "missing.example", "status": "FAILED", "report": None, "error": "No report"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            repository = VirusTotalRepository(Path(directory) / "vt.db")
            batch_id = repository.save_batch("Example", ["example.com", "missing.example"], results)
            batch = repository.get_batch(batch_id)
            self.assertEqual(len(batch["results"]), 2)
            self.assertEqual(repository.list_batches()[0]["domain_count"], 2)
            report_path = Path(directory) / "combined.docx"
            report_path.write_bytes(build_batch_docx(batch))
            text = "\n".join(p.text for p in Document(report_path).paragraphs)
            self.assertIn("Combined VirusTotal intelligence report", text)
            self.assertIn("example.com", text)
            self.assertIn("missing.example", text)
            self.assertIn("Last observed DNS records", text)
            self.assertIn("Test CA", text)
            self.assertIn("www.example.com", text)


if __name__ == "__main__":
    unittest.main()
