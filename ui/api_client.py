from __future__ import annotations

import os
from typing import Any

import requests


class APIClientError(RuntimeError):
    """A controlled error returned when the framework API cannot serve a request."""


class FrameworkAPIClient:
    def __init__(
        self,
        base_url: str | None = None,
        session: requests.Session | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("API_BASE_URL", "http://localhost:8000")).rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout

    def submit_osint(
        self,
        target: str,
        collectors: list[str],
        *,
        brand: str = "",
        resolution: dict[str, Any] | None = None,
        query_budget: int = 12,
        authorized: bool,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/jobs/osint",
            json={
                "target": target,
                "collectors": collectors,
                "brand": brand,
                "resolution": resolution,
                "query_budget": query_budget,
                "authorized": authorized,
            },
        )

    def submit_dynamic(
        self,
        target: str,
        max_pages: int,
        *,
        authorized: bool,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/jobs/dynamic",
            json={"target": target, "max_pages": max_pages, "authorized": authorized},
        )

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/jobs/{job_id}")

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/jobs/{job_id}/cancel")

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        try:
            response = self.session.request(
                method, f"{self.base_url}{path}", timeout=self.timeout, **kwargs
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            detail = ""
            response = getattr(exc, "response", None)
            if response is not None:
                try:
                    detail = str(response.json().get("detail", ""))
                except (ValueError, AttributeError):
                    detail = response.text[:300]
            message = detail or str(exc) or "Framework API is unavailable"
            raise APIClientError(message) from exc
