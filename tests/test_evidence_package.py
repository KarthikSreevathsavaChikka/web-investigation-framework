import io
import unittest
import zipfile

from services.evidence.package import build_package, verify_package


class EvidencePackageTests(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(verify_package(build_package({'original.png': b'original'}))['valid'])

    def test_detects_changes_missing_and_extra_files(self):
        original = build_package({'a': b'original', 'b': b'other'})
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(original)) as source:
            with zipfile.ZipFile(output, 'w') as target:
                target.writestr('manifest.json', source.read('manifest.json'))
                target.writestr('a', b'changed')
                target.writestr('extra', b'extra')
        result = verify_package(output.getvalue())
        self.assertFalse(result['valid'])
        self.assertEqual(result['missing'], ['b'])
        self.assertEqual(result['altered'], ['a'])
        self.assertEqual(result['unexpected'], ['extra'])

    def test_rejects_unsafe_names(self):
        with self.assertRaises(ValueError):
            build_package({'../outside': b'x'})
