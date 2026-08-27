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

    def test_submits_dynamic_job_and_reads_status(self):
        session = FakeSession(FakeResponse({"id": "JOB_2", "status": "RUNNING"}))
        client = FrameworkAPIClient("http://api:8000", session=session)
        client.submit_dynamic("https://example.com", 5, authorized=True)
        client.get_job("JOB_2")
        self.assertEqual(session.calls[0][2]["json"]["max_pages"], 5)
        self.assertEqual(session.calls[1][1], "http://api:8000/api/v1/jobs/JOB_2")

    def test_surfaces_fastapi_error_detail(self):
        session = FakeSession(FakeResponse({"detail": "Queue unavailable"}, status_code=503))
        client = FrameworkAPIClient("http://api:8000", session=session)
        with self.assertRaisesRegex(APIClientError, "Queue unavailable"):
            client.get_job("JOB_3")


if __name__ == "__main__":
    unittest.main()
