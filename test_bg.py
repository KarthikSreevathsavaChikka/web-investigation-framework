import asyncio
from core.browser_engine import PlaywrightInvestigationEngine
from database.db_manager import DatabaseManager

async def test():
    db = DatabaseManager("test.db")
    engine = PlaywrightInvestigationEngine(db, max_pages=15)
    await engine.run_investigation("https://parimatchs123.com/", "TEST")

asyncio.run(test())
