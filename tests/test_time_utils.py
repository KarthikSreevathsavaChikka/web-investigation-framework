import unittest

from core.time_utils import format_ist, now_ist


class TimeUtilsTests(unittest.TestCase):
    def test_formats_utc_timestamp_as_24_hour_ist(self):
        self.assertEqual(format_ist("2026-09-10T18:45:30+00:00"), "11-09-2026 00:15:30 IST")

    def test_naive_timestamp_is_treated_as_utc(self):
        self.assertEqual(format_ist("2026-09-10T06:00:00"), "10-09-2026 11:30:00 IST")

    def test_preserves_non_timestamp_values(self):
        self.assertEqual(format_ist("2026-09", fallback=""), "2026-09")
        self.assertEqual(format_ist("2026-09-10", fallback=""), "2026-09-10")
        self.assertEqual(format_ist(None, fallback="Waiting"), "Waiting")

    def test_now_ist_is_timezone_aware(self):
        current = now_ist()
        self.assertIsNotNone(current.utcoffset())
        self.assertEqual(current.utcoffset().total_seconds(), 19_800)


if __name__ == "__main__":
    unittest.main()
