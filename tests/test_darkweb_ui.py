import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


class DarkwebUITests(unittest.TestCase):
    def test_empty_workspace_and_submission(self):
        with patch("ui.darkweb_workspace.FrameworkAPIClient") as factory:
            client = factory.return_value
            client.list_jobs.return_value = []
            client.submit_darkweb.return_value = {"id": "JOB_NEW"}
            app = AppTest.from_string("from ui.darkweb_workspace import render_darkweb_workspace\nrender_darkweb_workspace()")
            app.run()
            self.assertFalse(app.exception)
            app.text_input[0].set_value("partimatch123.com")
            app.text_area[0].set_value("http://supplied-source.onion/")
            app.button[0].click().run()
            self.assertFalse(app.exception)
            client.submit_darkweb.assert_called_once_with("partimatch123.com", ["http://supplied-source.onion/"])

    def test_saved_partial_result_is_visible(self):
        job = {"id": "JOB_SAVED", "component": "darkweb", "target": "partimatch123.com",
               "status": "COMPLETED", "created_at": "2026-10-05", "result": {
                   "supplied_sources": 1, "retrieved_sources": 0, "matched_sources": 0,
                   "coverage": "PARTIAL", "scope": "Supplied sources only", "evidence_scope": "Excerpts only",
                   "sources": [{"source_url": "http://source.onion/", "status": "unavailable",
                                "retrieved_at": "2026-10-05", "error": "Offline", "matches": []}]}}
        with patch("ui.darkweb_workspace.FrameworkAPIClient") as factory:
            factory.return_value.list_jobs.return_value = [job]
            factory.return_value.get_job.return_value = job
            app = AppTest.from_string("from ui.darkweb_workspace import render_darkweb_workspace\nrender_darkweb_workspace()")
            app.run()
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, "1")
            self.assertTrue(any("PARTIAL" in item.value for item in app.markdown))


if __name__ == "__main__":
    unittest.main()
