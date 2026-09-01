from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
import uuid

from core.browser_engine import PlaywrightInvestigationEngine
from core.validator import TargetValidator
from database.db_manager import DatabaseManager
from osint.orchestrator import IntelligenceOrchestrator
from osint.cancellation import InvestigationCancelled
from osint.models import TargetCandidate, TargetResolution
from services.jobs.queue import RedisJobQueue
from services.jobs.repository import JobRepository

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("investigation-worker")
stopping = False
DEFAULT_DYNAMIC_JOB_TIMEOUT_SECONDS = 900
WORKER_HEARTBEAT_INTERVAL_SECONDS = 5


def _request_stop(*_args) -> None:
    global stopping
    stopping = True


def execute_job(job: dict, cancel_check=None) -> dict:
    payload = job["payload"]
    if job["component"] == "osint":
        resolution_data = payload.get("resolution")
        resolution = None
        if resolution_data:
            resolution = TargetResolution(
                original_input=resolution_data["original_input"],
                normalized_input=resolution_data["normalized_input"],
                input_type=resolution_data["input_type"],
                resolved_brand=resolution_data["resolved_brand"],
                candidates=[TargetCandidate(**item) for item in resolution_data.get("candidates", [])],
            )
        investigation_id = IntelligenceOrchestrator().run(
            payload["target"],
            payload["collectors"],
            brand=payload.get("brand", ""),
            resolution=resolution,
            query_budget=int(payload.get("query_budget", 12)),
            cancel_check=cancel_check,
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
    timeout_seconds = max(
        30,
        int(
            os.getenv(
                "DYNAMIC_JOB_TIMEOUT_SECONDS",
                str(DEFAULT_DYNAMIC_JOB_TIMEOUT_SECONDS),
            )
        ),
    )

    async def run_dynamic_investigation() -> dict:
        task = asyncio.create_task(
            engine.run_investigation(
                validation["final_url"],
                investigation_id,
                allow_manual_auth=False,
            )
        )
        elapsed = 0
        while not task.done() and elapsed < timeout_seconds:
            if cancel_check and cancel_check():
                engine.request_stop()
            done, _ = await asyncio.wait({task}, timeout=1)
            if done:
                break
            elapsed += 1
        if not task.done():
            task.cancel()
            raise TimeoutError
        result = await task
        if cancel_check and cancel_check():
            raise InvestigationCancelled("Investigation cancelled by operator")
        return result

    try:
        result = asyncio.run(run_dynamic_investigation())
    except TimeoutError as exc:
        raise RuntimeError(
            f"Dynamic investigation exceeded the {timeout_seconds}-second worker limit"
        ) from exc
    if result.get("status") == "FAILED":
        raise RuntimeError(result.get("error", "Dynamic investigation failed"))
    return {"investigation_id": investigation_id, "component": "dynamic", **result}


def run() -> None:
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    repository = JobRepository()
    queue = RedisJobQueue()
    heartbeat_stop = threading.Event()

    def maintain_heartbeat() -> None:
        while not heartbeat_stop.is_set():
            try:
                queue.heartbeat()
            except Exception:
                logger.exception("Unable to update worker heartbeat")
            heartbeat_stop.wait(WORKER_HEARTBEAT_INTERVAL_SECONDS)

    heartbeat_thread = threading.Thread(
        target=maintain_heartbeat,
        name="worker-heartbeat",
        daemon=True,
    )
    heartbeat_thread.start()
    recovered = queue.recover_unacknowledged()
    if recovered:
        logger.warning("Recovered %s unacknowledged job(s)", recovered)
    logger.info("Worker ready; waiting for investigation jobs")
    try:
        while not stopping:
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
            if job["status"] in {"CANCELLING", "CANCELLED"} or queue.cancellation_requested(job_id):
                repository.mark_cancelled(job_id)
                queue.acknowledge(job_id)
                queue.clear_cancellation(job_id)
                continue
            job = repository.mark_running(job_id)
            logger.info("Running %s job %s for %s", job["component"], job_id, job["target"])
            try:
                repository.mark_completed(
                    job_id,
                    execute_job(job, lambda: queue.cancellation_requested(job_id)),
                )
                logger.info("Completed job %s", job_id)
            except InvestigationCancelled:
                logger.info("Cancelled job %s", job_id)
                repository.mark_cancelled(job_id)
            except Exception as exc:
                logger.exception("Job %s failed", job_id)
                repository.mark_failed(job_id, str(exc))
            finally:
                queue.acknowledge(job_id)
                queue.clear_cancellation(job_id)
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=WORKER_HEARTBEAT_INTERVAL_SECONDS + 1)


if __name__ == "__main__":
    run()
