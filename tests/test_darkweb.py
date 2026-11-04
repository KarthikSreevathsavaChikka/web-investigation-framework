import base64
import hashlib
import os
import time
import unittest
from unittest.mock import MagicMock, patch

import requests
from fastapi.testclient import TestClient

from osint.cancellation import InvestigationCancelled
from osint.darkweb import collect_darkweb, extract_evidence, fetch_onion, MAX_BYTES
from osint.onion_urls import normalize_onion_url
from services.api.schemas import DarkwebJobRequest
from services.api.main import app
from services.api.dependencies import get_job_queue, get_job_repository


def onion(seed=1):
    key = bytes([seed]) * 32
    checksum = hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2]
    return "http://" + base64.b32encode(key + checksum + b"\x03").decode().lower() + ".onion/"


def response(body=b"example.com", status=200, headers=None):
    value = MagicMock()
    value.__enter__.return_value = value
    value.status_code = status
    value.is_redirect = status in {301, 302, 303, 307, 308}
    value.headers = headers or {"Content-Type": "text/html"}
    value.encoding = "utf-8"
    value.iter_content.return_value = [body]
    return value


class DarkwebTests(unittest.TestCase):
    def test_url_validation_and_checksum(self):
        self.assertEqual(normalize_onion_url(onion() + "#fragment"), onion())
        for url in ["http://localhost/", "http://127.0.0.1/", "https://example.com/",
                    onion().replace("http://", "file://"), onion().replace("http://", "http://user:pass@"),
                    "http://" + "a" * 56 + ".onion/", onion().replace(".onion/", ".onion:8080/"),
                    onion() + "\npath"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_onion_url(url)

    def test_target_and_sources_validated_by_api_schema(self):
        request = DarkwebJobRequest(target="https://partimatch123.com/path", onion_urls=[onion(), onion()], authorized=True)
        self.assertEqual(request.target, "partimatch123.com")
        self.assertEqual(len(request.onion_urls), 1)
        with self.assertRaises(ValueError):
            DarkwebJobRequest(target=onion(), onion_urls=[onion()], authorized=True)

    def test_exact_matches_not_similar_hosts(self):
        page = b'<title>Discussion</title><p>fakeexample.com example.com.evil example.com</p><a href="https://example.com/help">Visit</a>'
        result = extract_evidence(page, "text/html", "utf-8", "example.com")
        self.assertEqual(result["status"], "matched")
        self.assertEqual([m["field"] for m in result["matches"]], ["text", "link"])
        clean = extract_evidence(b'<script>example.com</script><p>fakeexample.com example.com.evil</p>', "text/html", "utf-8", "example.com")
        self.assertEqual(clean["status"], "no_match")

    def test_matching_scans_beyond_display_excerpt(self):
        result = extract_evidence(b"x " * 10000 + b" example.com", "text/plain", "utf-8", "example.com")
        self.assertEqual(result["status"], "matched")
        self.assertIn("example.com", result["matches"][0]["excerpt"])

    def test_sentence_punctuation_is_not_a_hostname_suffix(self):
        result = extract_evidence(b"Visit example.com. Then example.com.evil", "text/plain", "utf-8", "example.com")
        self.assertEqual(len(result["matches"]), 1)

    def test_restricted_pages_not_reported_as_no_match(self):
        for body in [b'<input type="password">', b'<title>Verify you are human</title>']:
            self.assertEqual(extract_evidence(body, "text/html", "utf-8", "example.com")["status"], "restricted")

    def test_redirect_rejects_other_hosts_before_fetch(self):
        for destination in ["http://127.0.0.1/", "https://example.com/", onion(2)]:
            session = MagicMock()
            session.get.return_value = response(status=302, headers={"Location": destination})
            with self.assertRaises(ValueError):
                fetch_onion(session, onion(), deadline=time.monotonic()+60)
            self.assertEqual(session.get.call_count, 1)

    def test_same_host_redirect_and_response_closed(self):
        session = MagicMock()
        first, second = response(status=302, headers={"Location": "/page"}), response()
        session.get.side_effect = [first, second]
        result = fetch_onion(session, onion(), deadline=time.monotonic()+60)
        self.assertEqual(result["final_url"], onion() + "page")
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        first.__exit__.assert_called_once()
        second.__exit__.assert_called_once()

    def test_size_limit_and_cancellation(self):
        session = MagicMock()
        session.get.return_value = response(b"x" * (MAX_BYTES+1))
        with self.assertRaises(ValueError):
            fetch_onion(session, onion(), deadline=time.monotonic()+60)
        with self.assertRaises(InvestigationCancelled):
            fetch_onion(session, onion(), deadline=time.monotonic()+60, cancel_check=lambda: True)

    def test_failed_tor_has_no_direct_fallback_and_partial_coverage(self):
        with patch.dict(os.environ, {"DARKWEB_TOR_PROXY": "socks5h://tor:9050"}), patch("osint.darkweb.requests.Session") as factory:
            session = factory.return_value.__enter__.return_value
            session.get.side_effect = requests.ConnectionError("proxy connection failed")
            result = collect_darkweb({"target": "example.com", "onion_urls": [onion()]})
            self.assertEqual(result["coverage"], "PARTIAL")
            self.assertEqual(result["sources"][0]["status"], "unavailable")
            self.assertEqual(session.get.call_count, 1)
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies["http"], "socks5h://tor:9050")

    def test_missing_proxy_fails_explicitly(self):
        with patch.dict(os.environ, {"DARKWEB_TOR_PROXY": ""}), self.assertRaisesRegex(RuntimeError, "not configured"):
            collect_darkweb({"target": "example.com", "onion_urls": [onion()]})

    def test_successful_evidence_and_hash(self):
        with patch.dict(os.environ, {"DARKWEB_TOR_PROXY": "socks5h://tor:9050"}), patch("osint.darkweb.requests.Session") as factory:
            factory.return_value.__enter__.return_value.get.return_value = response()
            result = collect_darkweb({"target": "example.com", "onion_urls": [onion()]})
        self.assertEqual(result["coverage"], "COMPLETED")
        self.assertEqual(result["matched_sources"], 1)
        self.assertEqual(result["sources"][0]["content_sha256"], hashlib.sha256(b"example.com").hexdigest())

    def test_job_api_queues_and_rejects_invalid_source(self):
        repository, queue = MagicMock(), MagicMock()
        saved = {"id": "JOB_DARK", "component": "darkweb", "target": "example.com", "status": "QUEUED",
                 "attempts": 0, "created_at": "2026-10-05T00:00:00Z", "payload": {}, "result": {}}
        repository.create.return_value = saved
        repository.get.return_value = saved
        app.dependency_overrides[get_job_repository] = lambda: repository
        app.dependency_overrides[get_job_queue] = lambda: queue
        try:
            with TestClient(app) as client:
                result = client.post("/api/v1/jobs/darkweb", json={"target": "example.com", "onion_urls": [onion()], "authorized": True})
                self.assertEqual(result.status_code, 202)
                queue.enqueue.assert_called_once_with("JOB_DARK")
                bad = client.post("/api/v1/jobs/darkweb", json={"target": "example.com", "onion_urls": ["http://localhost"], "authorized": True})
                self.assertEqual(bad.status_code, 422)
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
