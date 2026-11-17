import unittest

from netlab.server import ScanDetector


class ScanDetectorTest(unittest.TestCase):
    def test_below_threshold_stays_quiet(self):
        det = ScanDetector(threshold=4, window=10.0)
        for i, port in enumerate([9021, 9022, 9025]):
            self.assertIsNone(det.record("127.0.0.1", port, now=float(i)))
        self.assertEqual(det.alerts, [])

    def test_threshold_triggers_alert(self):
        det = ScanDetector(threshold=4, window=10.0)
        for i, port in enumerate([9021, 9022, 9025]):
            det.record("127.0.0.1", port, now=float(i))
        alert = det.record("127.0.0.1", 9080, now=3.0)
        self.assertIsNotNone(alert)
        self.assertIn("127.0.0.1", alert)
        self.assertEqual(len(det.alerts), 1)

    def test_same_port_repeatedly_is_not_a_scan(self):
        det = ScanDetector(threshold=3, window=10.0)
        for i in range(10):
            self.assertIsNone(det.record("127.0.0.1", 9022, now=float(i)))

    def test_slow_probing_does_not_alert(self):
        det = ScanDetector(threshold=3, window=10.0)
        # one port every 20 seconds: outside any 10s window
        for i, port in enumerate([9001, 9002, 9003, 9004]):
            self.assertIsNone(det.record("127.0.0.1", port, now=i * 20.0))

    def test_sources_tracked_independently(self):
        det = ScanDetector(threshold=3, window=10.0)
        det.record("127.0.0.1", 9001, now=0.0)
        det.record("::1", 9001, now=0.0)
        self.assertIsNone(det.record("127.0.0.1", 9002, now=1.0))
        self.assertIsNone(det.record("::1", 9002, now=1.0))

    def test_rearm_after_alert(self):
        det = ScanDetector(threshold=3, window=10.0)
        for i, port in enumerate([9001, 9002]):
            det.record("127.0.0.1", port, now=float(i))
        self.assertIsNotNone(det.record("127.0.0.1", 9003, now=2.0))
        # queue cleared: a fresh burst is needed for the next alert
        self.assertIsNone(det.record("127.0.0.1", 9004, now=3.0))
        self.assertEqual(len(det.alerts), 1)

    def test_threshold_must_be_at_least_two(self):
        with self.assertRaises(ValueError):
            ScanDetector(threshold=1)


if __name__ == "__main__":
    unittest.main()
