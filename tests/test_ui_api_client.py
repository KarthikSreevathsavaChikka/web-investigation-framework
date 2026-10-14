import unittest

import requests

from ui.api_client import APIClientError, FrameworkAPIClient


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.HTTPError(f"HTTP {self.status_code}")
            error.response = self
            raise error

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response


class FrameworkAPIClientTests(unittest.TestCase):
    def test_submits_osint_resolution_to_versioned_job_endpoint(self):
        session = FakeSession(FakeResponse({"id": "JOB_1", "status": "QUEUED"}))
        client = FrameworkAPIClient("http://api:8000/", session=session)

        response = client.submit_osint(
            "example.com",
            ["DNS", "RDAP"],
            brand="Example",
            resolution={"original_input": "Example"},
            authorized=True,
        )

        self.assertEqual(response["id"], "JOB_1")
        method, url, options = session.calls[0]
        self.assertEqual((method, url), ("POST", "http://api:8000/api/v1/jobs/osint"))
        self.assertTrue(options["json"]["authorized"])
        self.assertEqual(options["json"]["resolution"]["original_input"], "Example")

    def test_submits_selected_domains_as_one_virustotal_batch(self):
        session = FakeSession(FakeResponse({"id": "JOB_VT", "status": "QUEUED"}))
        client = FrameworkAPIClient("http://api:8000", session=session)
        client.submit_virustotal(["one.example", "two.example"], brand="Example", authorized=True)
        method, url, options = session.calls[0]
        self.assertEqual((method, url), ("POST", "http://api:8000/api/v1/jobs/virustotal"))
        self.assertEqual(options["json"]["domains"], ["one.example", "two.example"])

    def test_surfaces_fastapi_error_detail(self):
        session = FakeSession(FakeResponse({"detail": "Queue unavailable"}, status_code=503))
        client = FrameworkAPIClient("http://api:8000", session=session)
        with self.assertRaisesRegex(APIClientError, "Queue unavailable"):
            client.get_job("JOB_3")

    def test_requests_job_cancellation(self):
        session = FakeSession(FakeResponse({"id": "JOB_4", "status": "CANCELLING"}))
        client = FrameworkAPIClient("http://api:8000", session=session)
        response = client.cancel_job("JOB_4")
        self.assertEqual(response["status"], "CANCELLING")
        self.assertEqual(
            session.calls[0][:2],
            ("POST", "http://api:8000/api/v1/jobs/JOB_4/cancel"),
        )

    def test_lists_jobs_with_the_configured_limit(self):
        session = FakeSession(FakeResponse({"items": [{"id": "JOB_5"}], "total": 1}))
        client = FrameworkAPIClient("http://api:8000", session=session)
        self.assertEqual(client.list_jobs(limit=200), [{"id": "JOB_5"}])
        self.assertEqual(session.calls[0][:2], ("GET", "http://api:8000/api/v1/jobs"))
        self.assertEqual(session.calls[0][2]["params"], {"limit": 200})


if __name__ == "__main__":
    unittest.main()
