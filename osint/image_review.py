"""Bounded multimodal summaries for stored screenshots using LM Studio."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from PIL import Image

from config import BASE_DIR
from core.time_utils import now_ist
from osint.cancellation import InvestigationCancelled
from osint.models import CollectorResult, Observation


PROMPT_VERSION = "screenshot-summary-v1"
FIELDS = {"summary", "visible_text", "relevance"}


def validate_image_summary(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("Invalid screenshot-summary fields")
    if value["relevance"] not in {"relevant", "uncertain", "unrelated"}:
        raise ValueError("Invalid screenshot relevance")
    for field, limit in (("summary", 700), ("visible_text", 500)):
        if not isinstance(value[field], str) or len(value[field]) > limit:
            raise ValueError(f"Invalid {field}")
    if not value["summary"].strip():
        raise ValueError("Screenshot summary is empty")
    return value


def screenshot_tasks(repository, investigation_id: str) -> list[dict]:
    tasks: dict[str, dict] = {}
    for item in repository.get_evidence(investigation_id):
        path = item.get("screenshot_path")
        if path:
            tasks.setdefault(path, {"path": path, "sha256": item.get("sha256"), "source_url": item.get("source_url"),
                "kind": "web_evidence", "context": item.get("context_text") or item.get("evidence_text") or ""})
    for item in repository.get_social_findings(investigation_id):
        for path in item.get("screenshot_paths") or []:
            tasks.setdefault(path, {"path": path, "sha256": None, "source_url": item.get("post_url"),
                "kind": "social_capture", "context": item.get("post_text") or item.get("title") or ""})
    for item in repository.get_documents(investigation_id):
        for capture in item.get("page_screenshots") or []:
            path = capture.get("path")
            if path:
                tasks.setdefault(path, {"path": path, "sha256": capture.get("sha256"), "source_url": item.get("source_url"),
                    "kind": "document_page", "context": item.get("evidence_context") or ""})
    return list(tasks.values())


class ScreenshotSummarizer:
    def __init__(self):
        base = os.getenv("LM_STUDIO_BASE_URL", "http://10.244.1.54:1234").rstrip("/")
        self.url = base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")
        self.model = os.getenv("LM_STUDIO_MODEL", "google/gemma-4-e4b")
        self.api_key = os.getenv("LM_STUDIO_API_KEY", "")
        self.timeout = max(5, min(float(os.getenv("OSINT_LLM_IMAGE_TIMEOUT", "30")), 90))
        # A zero budget means every stored screenshot. The time limit remains a
        # safety boundary for an unreachable or very slow model server.
        self.budget = max(0, min(int(os.getenv("OSINT_LLM_IMAGE_REVIEW_BUDGET", "0")), 500))
        self.seconds = max(10, min(float(os.getenv("OSINT_LLM_IMAGE_STAGE_SECONDS", "3600")), 3_600))
        self.prompt = (BASE_DIR / "config" / "screenshot_summary.txt").read_text()
        self.prompt_hash = hashlib.sha256(self.prompt.encode()).hexdigest()

    @staticmethod
    def _image_data(path: Path) -> tuple[str, str]:
        raw = path.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        with Image.open(io.BytesIO(raw)) as image:
            image = image.convert("RGB")
            image.thumbnail((1280, 1280))
            output = io.BytesIO()
            image.save(output, "JPEG", quality=78, optimize=True)
        return "data:image/jpeg;base64," + base64.b64encode(output.getvalue()).decode(), sha256

    def summarize(self, target, task: dict, timeout: float) -> dict:
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Invalid LM Studio server address")
        image_data, actual_sha = self._image_data(Path(task["path"]))
        context = {"target": {"domain": target.domain, "url": target.url, "brand": target.brand},
                   "source_url": task.get("source_url"), "capture_kind": task["kind"],
                   "source_context": str(task.get("context") or "")[:2000]}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        schema = {"type": "json_schema", "json_schema": {"name": "screenshot_summary", "strict": True,
            "schema": {"type": "object", "additionalProperties": False, "required": sorted(FIELDS), "properties": {
                "summary": {"type": "string", "minLength": 1, "maxLength": 700},
                "visible_text": {"type": "string", "maxLength": 500},
                "relevance": {"type": "string", "enum": ["relevant", "uncertain", "unrelated"]}}}}}
        response = requests.post(self.url, json={"model": self.model, "messages": [
            {"role": "system", "content": self.prompt},
            {"role": "user", "content": [{"type": "text", "text": json.dumps(context, ensure_ascii=False)},
                {"type": "image_url", "image_url": {"url": image_data}}]}],
            "temperature": 0, "max_tokens": 220, "stream": False, "response_format": schema,
        }, headers=headers, timeout=timeout, allow_redirects=False)
        try:
            if response.status_code != 200:
                raise ValueError(f"LM Studio HTTP {response.status_code}")
            answer = response.json()["choices"][0]["message"]["content"]
            value = validate_image_summary(json.loads(answer))
            return {**value, "sha256": actual_sha, "model": self.model, "prompt_version": PROMPT_VERSION,
                    "prompt_sha256": self.prompt_hash, "reviewed_at": now_ist().isoformat(), "review_status": "reviewed"}
        finally:
            response.close()

    def run(self, target, tasks: list[dict], *, cancel_check=None) -> CollectorResult:
        started = time.monotonic()
        observations, failures = [], 0
        selected_tasks = tasks if self.budget == 0 else tasks[:self.budget]
        for task in selected_tasks:
            if cancel_check and cancel_check():
                raise InvestigationCancelled("Cancelled during screenshot summarization")
            remaining = self.seconds - (time.monotonic() - started)
            if remaining <= 0:
                break
            try:
                review = self.summarize(target, task, min(self.timeout, remaining))
            except Exception:
                # One retry handles transient LAN/model-server failures without
                # abandoning all screenshots that follow this one.
                try:
                    remaining = self.seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        raise TimeoutError("Screenshot summary stage time exhausted")
                    review = self.summarize(target, task, min(self.timeout, remaining))
                except Exception as exc:
                    failures += 1
                    review = {"summary": "Visual summary unavailable; inspect the original screenshot.", "visible_text": "",
                        "relevance": "uncertain", "sha256": task.get("sha256") or "", "model": self.model,
                        "prompt_version": PROMPT_VERSION, "review_status": "unavailable", "error": type(exc).__name__,
                        "reviewed_at": now_ist().isoformat()}
            review.update({"screenshot_path": task["path"], "source_url": task.get("source_url"), "capture_kind": task["kind"]})
            observations.append(Observation("llm_screenshot_summary", "Advisory visual summary", "LLM_SCREENSHOT_SUMMARY",
                task["path"], task.get("source_url") or target.url, confidence=0.0, metadata=review))
        skipped = len(tasks) - len(observations)
        return CollectorResult("llm_screenshot_summary", "PARTIAL" if failures or skipped else "COMPLETED", observations,
            error=f"{len(observations)}/{len(tasks)} summarized; {failures} unavailable; {skipped} outside budget or skipped.",
            duration_seconds=time.monotonic() - started)
