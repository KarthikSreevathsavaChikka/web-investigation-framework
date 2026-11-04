import tempfile
import unittest
from pathlib import Path
from services.entity_index import EntityIndex
from services.api.routers.entities import demo

class EntityDemoTests(unittest.TestCase):
    def test_demo_matches_only_related_investigation(self):
        import asyncio
        result = asyncio.run(demo())
        self.assertEqual({r['investigation_id'] for r in result['connections']}, {'DEMO-B'})
        self.assertEqual({r['kind'] for r in result['connections']}, {'email', 'payment'})
        self.assertTrue(all(r['source'] and r['matching_source'] for r in result['connections']))

    def test_index_is_durable_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'index.db'
            index = EntityIndex(path)
            for _ in range(2):
                index.observe('a', 'source-a', 'HELP@Example.org')
            index.observe('b', 'source-b', 'help@example.org')
            self.assertEqual(len(EntityIndex(path).results('a')['connections']), 1)

    def test_api_demo(self):
        from fastapi import FastAPI
        import asyncio
        import httpx
        from services.api.routers.entities import router
        app = FastAPI()
        app.include_router(router)
        async def exercise():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
                response = await client.get('/api/v1/entities/demo')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.json()['connections']), 2)
        asyncio.run(exercise())
