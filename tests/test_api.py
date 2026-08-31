import unittest

from fastapi.testclient import TestClient

from services.api.dependencies import (
    get_dynamic_repository,
    get_job_queue,
    get_job_repository,
    get_osint_repository,
)
from services.api.main import app


class FakeDynamicRepository:
    def get_all_investigations(self):
        return [{
            "id": "DYNAMIC_1", "website_url": "https://example.com",
            "start_time": "2026-08-27T10:00:00", "end_time": None,
            "investigation_status": "COMPLETED",
        }]

    def get_investigation_summary(self, investigation_id):
        if investigation_id != "DYNAMIC_1":
            return {"investigation": {}}
        return {"investigation": self.get_all_investigations()[0], "pages_visited": 3}


class FakeOSINTRepository:
    def list_investigations(self):
        return [{
            "id": "OSINT_1", "target_domain": "example.org",
            "started_at": "2026-08-27T11:00:00", "completed_at": None,
            "status": "COMPLETED",
        }]

    def get_investigation(self, investigation_id):
        return self.list_investigations()[0] if investigation_id == "OSINT_1" else {}

    def get_summary_counts(self, investigation_id):
        return {"configured_queries": 50, "pages_visited": 8}


class FakeJobRepository:
    def __init__(self):
        self.jobs = {}

    def create(self, component, target, payload):
        job = {
            "id": "JOB_1", "component": component, "target": target,
            "status": "QUEUED", "attempts": 0,
            "created_at": "2026-08-27T12:00:00+00:00",
            "started_at": None, "completed_at": None,
            "result": {}, "error": None, "payload": payload,
        }
        self.jobs[job["id"]] = job
        return job

    def get(self, job_id):
        return self.jobs.get(job_id)

    def list(self, limit=50):
        return list(self.jobs.values())[:limit]

    def mark_failed(self, job_id, error):
        self.jobs[job_id]["status"] = "FAILED"
        self.jobs[job_id]["error"] = error

    def mark_cancelling(self, job_id):
        self.jobs[job_id]["status"] = "CANCELLING"

    def mark_cancelled(self, job_id):
        self.jobs[job_id]["status"] = "CANCELLED"
        self.jobs[job_id]["completed_at"] = "2026-08-27T12:01:00+00:00"


class FakeJobQueue:
    def __init__(self):
        self.enqueued = []
        self.cancelled = set()

    def enqueue(self, job_id):
        self.enqueued.append(job_id)

    def request_cancel(self, job_id):
        self.cancelled.add(job_id)

    def remove_pending(self, job_id):
        if job_id not in self.enqueued:
            return False
        self.enqueued.remove(job_id)
        return True

    def clear_cancellation(self, job_id):
        self.cancelled.discard(job_id)


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = FakeJobRepository()
        cls.queue = FakeJobQueue()
        app.dependency_overrides[get_dynamic_repository] = FakeDynamicRepository
        app.dependency_overrides[get_osint_repository] = FakeOSINTRepository
        app.dependency_overrides[get_job_repository] = lambda: cls.jobs
        app.dependency_overrides[get_job_queue] = lambda: cls.queue
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()

    def test_liveness(self):
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_lists_both_components_and_filters(self):
        response = self.client.get("/api/v1/investigations")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 2)
        filtered = self.client.get("/api/v1/investigations", params={"component": "osint"})
        self.assertEqual(filtered.json()["items"][0]["component"], "osint")

    def test_gets_details_and_returns_404(self):
        response = self.client.get("/api/v1/investigations/osint/OSINT_1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["summary"]["pages_visited"], 8)
        missing = self.client.get("/api/v1/investigations/dynamic/missing")
        self.assertEqual(missing.status_code, 404)

    def test_creates_and_reads_osint_job(self):
        response = self.client.post("/api/v1/jobs/osint", json={
            "target": "example.org",
            "collectors": ["DNS", "RDAP"],
            "brand": "Example",
            "authorized": True,
        })
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["status"], "QUEUED")
        self.assertEqual(self.queue.enqueued, ["JOB_1"])
        self.assertEqual(self.client.get("/api/v1/jobs/JOB_1").status_code, 200)

    def test_rejects_unconfirmed_authorization(self):
        response = self.client.post("/api/v1/jobs/dynamic", json={
            "target": "https://example.com", "max_pages": 5, "authorized": False,
        })
        self.assertEqual(response.status_code, 400)

    def test_cancels_a_queued_job_immediately(self):
        self.client.post("/api/v1/jobs/osint", json={
            "target": "cancel.example",
            "collectors": ["DNS"],
            "authorized": True,
        })
        response = self.client.post("/api/v1/jobs/JOB_1/cancel")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "CANCELLED")
        self.assertNotIn("JOB_1", self.queue.enqueued)


if __name__ == "__main__":
    unittest.main()
