from database.db_manager import DatabaseManager
from osint.storage import OSINTRepository
from services.jobs.queue import RedisJobQueue
from services.jobs.repository import JobRepository


def get_dynamic_repository() -> DatabaseManager:
    return DatabaseManager()


def get_osint_repository() -> OSINTRepository:
    return OSINTRepository()


def get_job_repository() -> JobRepository:
    return JobRepository()


def get_job_queue() -> RedisJobQueue:
    return RedisJobQueue()
