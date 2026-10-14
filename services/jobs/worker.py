from __future__ import annotations

import logging
import os
import signal
import threading
from dataclasses import asdict
from osint.orchestrator import IntelligenceOrchestrator
from osint.cancellation import InvestigationCancelled
from osint.models import TargetCandidate, TargetResolution
from osint.normalizer import target_for_domain
from osint.resolver import TargetResolver
from osint.search import build_keyless_search_provider
from services.jobs.queue import RedisJobQueue
from services.jobs.repository import JobRepository
from services.external_processing import execute_external_investigation, send_external_callback
from virustotal.client import VirusTotalClient, VirusTotalError
from virustotal.storage import VirusTotalRepository

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("investigation-worker")
stopping = False
WORKER_HEARTBEAT_INTERVAL_SECONDS = 5


def _request_stop(*_args) -> None:
    global stopping
    stopping = True


def execute_job(job: dict, cancel_check=None) -> dict:
    payload = job["payload"]
    if job["component"] == "darkweb":
        from osint.darkweb import collect_darkweb
        return collect_darkweb(payload, cancel_check)
    if job["component"] == "external":
        return execute_external_investigation(payload, cancel_check)
    if job["component"] == "virustotal":
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not configured in the worker")
        client = VirusTotalClient(api_key)
        results = []
        for domain in payload["domains"]:
            if cancel_check and cancel_check():
                raise InvestigationCancelled("VirusTotal batch cancelled by operator")
            try:
                results.append({"domain": domain, "status": "COMPLETED", "report": client.lookup(domain), "error": None})
            except (ValueError, VirusTotalError) as exc:
                results.append({"domain": domain, "status": "FAILED", "report": None, "error": str(exc)})
        batch_id = VirusTotalRepository().save_batch(payload.get("brand", ""), payload["domains"], results)
        return {"batch_id": batch_id, "component": "virustotal", "domain_count": len(results)}
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
        if resolution is None:
            resolution = TargetResolver().resolve(payload["target"], build_keyless_search_provider())
        if not resolution.candidates:
            raise RuntimeError(
                "No target domain could be resolved. Enter a full domain or refine the brand name."
            )
        selected_target = target_for_domain(payload["target"], resolution.candidates[0].domain)
        orchestrator = IntelligenceOrchestrator()
        investigation_id = orchestrator.run(
            selected_target,
            payload["collectors"],
            brand=payload.get("brand") or resolution.resolved_brand,
            resolution=resolution,
            query_budget=int(payload.get("query_budget", 12)),
            cancel_check=cancel_check,
        )
        coverage = orchestrator.repository.get_collection_coverage(investigation_id)
        return {
            "investigation_id": investigation_id,
            "component": "osint",
            "resolved_target": selected_target,
            "resolution": asdict(resolution),
            "coverage": coverage,
        }

    raise ValueError(f"Unsupported job component: {job['component']}")


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
                result = execute_job(job, lambda: queue.cancellation_requested(job_id))
                if job["component"] == "external":
                    send_external_callback(job["payload"], "COMPLETED", result=result)
                    result["callback_delivered"] = True
                repository.mark_completed(job_id, result)
                logger.info("Completed job %s", job_id)
            except InvestigationCancelled:
                logger.info("Cancelled job %s", job_id)
                repository.mark_cancelled(job_id)
            except Exception as exc:
                logger.exception("Job %s failed", job_id)
                repository.mark_failed(job_id, str(exc))
                if job["component"] == "external":
                    try:
                        send_external_callback(job["payload"], "FAILED", error=str(exc))
                    except Exception:
                        logger.exception("Unable to deliver failure callback for job %s", job_id)
            finally:
                queue.acknowledge(job_id)
                queue.clear_cancellation(job_id)
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=WORKER_HEARTBEAT_INTERVAL_SECONDS + 1)


if __name__ == "__main__":
    run()
