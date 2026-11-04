"""Retry missing screenshots in an existing investigation without repeating discovery.

Run from the project root: python -m scripts.repair_screenshots INVESTIGATION_ID
"""
import argparse
import asyncio
import json
import time

from config import EVIDENCE_DIR
from osint.evidence_capture import SERPEvidenceCapturePipeline
from osint.models import CollectorResult
from osint.orchestrator import public_social_capture_tasks
from osint.storage import OSINTRepository


async def repair(investigation_id: str) -> None:
    repository = OSINTRepository()
    investigation = repository.get_investigation(investigation_id)
    if not investigation:
        raise ValueError("Investigation not found")
    existing = {item["source_id"] for item in repository.get_evidence(investigation_id)}
    # Retry normal evidence sources plus every uncaptured finding, without a finding budget.
    tasks = {item["source_id"]: item for item in
             repository.get_evidence_tasks(investigation_id, 8)
             + public_social_capture_tasks(repository, investigation_id, 10_000)
             if item["source_id"] not in existing}
    pipeline = SERPEvidenceCapturePipeline(EVIDENCE_DIR)
    started = time.monotonic()
    captures = []
    # Persist each small batch so interrupted repairs can resume safely.
    pending = list(tasks.values())
    for offset in range(0, len(pending), 3):
        batch = await pipeline.capture(investigation_id, investigation["target_domain"],
                                       pending[offset:offset + 3], investigation.get("resolved_brand") or "")
        repository.save_page_captures(investigation_id, batch)
        captures.extend(batch)
        for item in batch:
            print(json.dumps({"url": item.source_url, "status": item.accessibility_status,
                              "screenshots": len(item.screenshots), "reason": item.failure_reason}), flush=True)
    unavailable = sum(not item.screenshots for item in captures)
    repository.save_collector_result(investigation_id, CollectorResult(
        "screenshot_repair", "PARTIAL" if unavailable else "COMPLETED",
        error=f"{unavailable} sources returned no screenshot; see page capture diagnostics." if unavailable else None,
        duration_seconds=time.monotonic() - started,
    ))
    print(json.dumps(repository.get_summary_counts(investigation_id)), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("investigation_id")
    args = parser.parse_args()
    asyncio.run(repair(args.investigation_id))
