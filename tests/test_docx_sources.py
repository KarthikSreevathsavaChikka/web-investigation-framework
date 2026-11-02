import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE as RT

from osint.docx_report import OSINTDocxReportBuilder
from osint.models import CollectorResult, Observation
from osint.normalizer import DomainNormalizer
from osint.storage import OSINTRepository


class DocxSourceTests(unittest.TestCase):
    def test_all_discovered_sources_have_clickable_links_without_captured_evidence(self):
        urls = [
            'https://1win-games.co.in/',
            'https://1win.com/casino',
            'https://1win-games.co.in/adminbox/',
            'https://1win-games.co.in/adminbox/assets/ext3/adapter/ext/ext-base.js',
            'https://1win-games.co.in/adminbox/assets/ext3/ext-all.js',
            'https://1win-games.co.in/adminbox/assets/ext3/resources/css/ext-all-notheme-min.css',
        ]
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'report.db')
            repo.create_investigation('TEST', DomainNormalizer.normalize(urls[0]))
            repo.save_collector_result('TEST', CollectorResult('wayback_cdx', 'COMPLETED', [
                Observation('wayback_cdx', 'Search', 'SEARCH_RESULT', f'Historical URL: {url}', url,
                    metadata={'query_id': 'WAYBACK_001', 'query_text': 'Historical URLs',
                              'search_engine': 'wayback_cdx', 'rank': rank, 'normalized_url': url,
                              'title': f'Historical URL: {url}', 'source_type': 'target_domain',
                              'snippet': 'Wayback capture timestamp: 20240823210451',
                              'relevance_status': 'accepted'})
                for rank, url in enumerate(urls, 1)
            ]))
            builder = OSINTDocxReportBuilder(repo)
            standalone = Document(BytesIO(builder.build('TEST')))
            combined = Document()
            builder.append(combined, 'TEST', heading_level=2)
            buffer = BytesIO()
            combined.save(buffer)
            combined = Document(BytesIO(buffer.getvalue()))
            for report in (standalone, combined):
                with self.subTest(combined=report is combined):
                    text = '\n'.join(p.text for p in report.paragraphs)
                    self.assertIn('Source URLs', text)
                    self.assertIn('Wayback capture timestamp: 20240823210451', text)
                    self.assertIn('Discovery query count: 1', text)
                    links = {r.target_ref for r in report.part.rels.values() if r.reltype == RT.HYPERLINK}
                    self.assertEqual(links, set(urls))
                    elements = report.element.xpath('.//w:hyperlink')
                    self.assertEqual(len(elements), len(urls))
                    self.assertEqual({''.join(e.xpath('.//w:t/text()')) for e in elements}, set(urls))

    def test_empty_sources_are_reported_and_unsafe_urls_are_plain_text(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = OSINTRepository(Path(directory) / 'report.db')
            repo.create_investigation('EMPTY', DomainNormalizer.normalize('example.com'))
            report = Document(BytesIO(OSINTDocxReportBuilder(repo).build('EMPTY')))
            self.assertIn('No source URLs were recorded.', [p.text for p in report.paragraphs])
            paragraph = report.add_paragraph()
            OSINTDocxReportBuilder._add_source_link(paragraph, 'javascript:alert(1)')
            self.assertEqual(paragraph.text, 'javascript:alert(1)')
            self.assertFalse(report.element.xpath('.//w:hyperlink'))


if __name__ == '__main__':
    unittest.main()
