import tempfile
import unittest
from pathlib import Path

from bs4 import BeautifulSoup

from osint.normalizer import DomainNormalizer
from osint.report import OSINTReportBuilder
from osint.storage import OSINTRepository
from osint.text_cleanup import clean_evidence_text


class ReportLayoutTests(unittest.TestCase):
    def test_extracted_document_controls_are_safe_for_word(self):
        from docx import Document
        from io import BytesIO
        report = Document()
        text = clean_evidence_text("Document\x00 text\x0bwith\x0cpage\x1f controls\ufffe")
        report.add_paragraph(text)
        output = BytesIO()
        report.save(output)
        self.assertIn("Document", text)
        self.assertTrue(output.getvalue().startswith(b'PK'))

    def test_empty_table_spans_only_its_real_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / "test.db")
            repo.create_investigation("EMPTY", DomainNormalizer.normalize("example.com"))
            soup = BeautifulSoup(OSINTReportBuilder(repo).build_html("EMPTY"), "html.parser")
            empty_tables = 0
            for table in soup.select("table"):
                cell = table.select_one("td[colspan]")
                if cell:
                    empty_tables += 1
                    self.assertEqual(int(cell["colspan"]), len(table.select("thead th")))
            self.assertGreater(empty_tables, 2)
