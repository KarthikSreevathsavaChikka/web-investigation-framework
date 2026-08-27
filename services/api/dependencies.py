from database.db_manager import DatabaseManager
from osint.storage import OSINTRepository


def get_dynamic_repository() -> DatabaseManager:
    return DatabaseManager()


def get_osint_repository() -> OSINTRepository:
    return OSINTRepository()
