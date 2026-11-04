from __future__ import annotations

import os

from redis import Redis


class RedisJobQueue:
    queue_name = "web-investigator:jobs"
    processing_name = "web-investigator:jobs:processing"
    cancel_prefix = "web-investigator:jobs:cancel:"

    def __init__(self, url: str | None = None) -> None:
        self.client = Redis.from_url(
            url or os.getenv("REDIS_URL", "redis://redis:6379/0"),
            decode_responses=True,
            socket_timeout=None,
        )

    def enqueue(self, job_id: str) -> None:
        self.client.lpush(self.queue_name, job_id)

    def dequeue(self, timeout: int = 5) -> str | None:
        return self.client.brpoplpush(self.queue_name, self.processing_name, timeout=timeout)

    def acknowledge(self, job_id: str) -> None:
        self.client.lrem(self.processing_name, 1, job_id)

    def remove_pending(self, job_id: str) -> bool:
        return bool(self.client.lrem(self.queue_name, 1, job_id))

    def request_cancel(self, job_id: str) -> None:
        self.client.set(f"{self.cancel_prefix}{job_id}", "1", ex=86_400)

    def cancellation_requested(self, job_id: str) -> bool:
        return bool(self.client.exists(f"{self.cancel_prefix}{job_id}"))

    def clear_cancellation(self, job_id: str) -> None:
        self.client.delete(f"{self.cancel_prefix}{job_id}")

    def recover_unacknowledged(self) -> int:
        recovered = 0
        while True:
            job_id = self.client.rpoplpush(self.processing_name, self.queue_name)
            if not job_id:
                return recovered
            recovered += 1

    def ping(self) -> bool:
        return bool(self.client.ping())

    def heartbeat(self) -> None:
        self.client.set("web-investigator:worker:heartbeat", "ready", ex=15)
