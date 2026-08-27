from __future__ import annotations

import asyncio
import logging
import os
import signal
import uuid

from core.browser_engine import PlaywrightInvestigationEngine
from core.validator import TargetValidator
from database.db_manager import DatabaseManager
from osint.orchestrator import IntelligenceOrchestrator
from services.jobs.queue import RedisJobQueue
from services.jobs.repository import JobRepository

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("investigation-worker")
stopping = False


def _request_stop(*_args) -> None:
    global stopping
    stopping = True


def execute_job(job: dict) -> dict:
    payload = job["payload"]
    if job["component"] == "osint":
        investigation_id = IntelligenceOrchestrator().run(
            payload["target"], payload["collectors"], brand=payload.get("brand", "")
        )
        return {"investigation_id": investigation_id, "component": "osint"}

    if job["component"] != "dynamic":
        raise ValueError(f"Unsupported job component: {job['component']}")

    validation = TargetValidator.validate_url(payload["target"])
    if not validation.get("valid"):
        raise ValueError(validation.get("error", "Target URL is not reachable"))
    investigation_id = f"INV_{uuid.uuid4().hex[:8].upper()}"
    engine = PlaywrightInvestigationEngine(
        DatabaseManager(), max_pages=int(payload.get("max_pages", 10))
    )
    result = asyncio.run(
        engine.run_investigation(validation["final_url"], investigation_id)
    )
    if result.get("status") == "FAILED":
        raise RuntimeError(result.get("error", "Dynamic investigation failed"))
    return {"investigation_id": investigation_id, "component": "dynamic", **result}


def run() -> None:
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    repository = JobRepository()
    queue = RedisJobQueue()
    recovered = queue.recover_unacknowledged()
    if recovered:
        logger.warning("Recovered %s unacknowledged job(s)", recovered)
    logger.info("Worker ready; waiting for investigation jobs")
    while not stopping:
        queue.heartbeat()
        job_id = queue.dequeue()
        if not job_id:
            continue
        job = repository.get(job_id)
        if not job:
            logger.warning("Ignoring missing job %s", job_id)
            queue.acknowledge(job_id)
            continue
        if job["status"] == "COMPLETED":
            queue.acknowledge(job_id)
            continue
        job = repository.mark_running(job_id)
        logger.info("Running %s job %s for %s", job["component"], job_id, job["target"])
        try:
            repository.mark_completed(job_id, execute_job(job))
            logger.info("Completed job %s", job_id)
        except Exception as exc:
            logger.exception("Job %s failed", job_id)
            repository.mark_failed(job_id, str(exc))
        finally:
            queue.acknowledge(job_id)


if __name__ == "__main__":
    run()
