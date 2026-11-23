import socket
import unittest
from unittest import mock

from netlab import scanner


class RequireLoopbackTest(unittest.TestCase):
    def test_loopback_addresses_pass(self):
        for host in ["127.0.0.1", "localhost", "::1"]:
            addrs = scanner.require_loopback(host)
            self.assertTrue(addrs)

    def test_numeric_public_ip_refused_without_network(self):
        # numeric: no DNS lookup happens, refusal must come first
        with self.assertRaises(ValueError):
            scanner.require_loopback("8.8.8.8")

    def test_refusal_happens_before_any_socket_use(self):
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                      ("203.0.113.9", 0))]
        with mock.patch.object(socket, "getaddrinfo",
                               return_value=fake_info), \
             mock.patch.object(socket, "socket",
                               side_effect=AssertionError("network touched")), \
             mock.patch.object(socket, "create_connection",
                               side_effect=AssertionError("network touched")):
            with self.assertRaises(ValueError):
                scanner.scan_ports("example.test", [80])

    def test_unresolvable_host_raises(self):
        with mock.patch.object(socket, "getaddrinfo",
                               side_effect=socket.gaierror("no such host")):
            with self.assertRaises(ValueError):
                scanner.require_loopback("does-not-exist.invalid")


class PortSpecTest(unittest.TestCase):
    def test_lists_and_ranges(self):
        self.assertEqual(scanner.parse_port_spec("9021,9030-9032"),
                         [9021, 9030, 9031, 9032])

    def test_duplicates_removed_and_sorted(self):
        self.assertEqual(scanner.parse_port_spec("9003,9001,9003"),
                         [9001, 9003])

    def test_bad_input_rejected(self):
        for bad in ["", "abc", "0", "70000", "9050-9010"]:
            with self.assertRaises(ValueError):
                scanner.parse_port_spec(bad)


class ScanPortsTest(unittest.TestCase):
    """End-to-end: scan a real LabServer running on ephemeral ports."""

    @classmethod
    def setUpClass(cls):
        from netlab.server import LabServer

        def free_port():
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                return probe.getsockname()[1]

        cls.open_ports = [free_port() for _ in range(3)]
        cls.closed_port = free_port()
        services = [
            {"port": cls.open_ports[0], "service": "ftp",
             "banner": "220 test ftp\r\n"},
            {"port": cls.open_ports[1], "service": "ssh",
             "banner": "SSH-2.0-test\r\n"},
            {"port": cls.open_ports[2], "service": "http", "banner": ""},
        ]
        cls.logs = []
        cls.server = LabServer(services=services, log=cls.logs.append)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_finds_exactly_the_open_ports(self):
        results = scanner.scan_ports(
            "127.0.0.1", self.open_ports + [self.closed_port])
        states = {r["port"]: r["state"] for r in results}
        for port in self.open_ports:
            self.assertEqual(states[port], "open")
        self.assertEqual(states[self.closed_port], "closed")

    def test_banners_captured(self):
        results = scanner.scan_ports("127.0.0.1", self.open_ports[:2])
        banners = {r["port"]: r["banner"] for r in results}
        self.assertEqual(banners[self.open_ports[0]], "220 test ftp")
        self.assertEqual(banners[self.open_ports[1]], "SSH-2.0-test")

    def test_result_fields(self):
        results = scanner.scan_ports("127.0.0.1", [self.open_ports[0]])
        res = results[0]
        self.assertEqual(set(res), {"port", "state", "service", "banner",
                                    "latency_ms"})
        self.assertGreaterEqual(res["latency_ms"], 0)

    def test_scan_triggers_detector_alert(self):
        def free_port():
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                return probe.getsockname()[1]

        logs = []
        ports = [free_port() for _ in range(3)]
        from netlab.server import LabServer, ScanDetector
        det = ScanDetector(threshold=3, window=10.0)
        srv = LabServer(services=[
            {"port": p, "service": "ftp", "banner": "220 x\r\n"}
            for p in ports], detector=det, log=logs.append)
        srv.start()
        try:
            scanner.scan_ports("127.0.0.1", ports)
        finally:
            srv.stop()
        self.assertTrue(any("ALERT" in line for line in logs))
        self.assertEqual(len(det.alerts), 1)

    def test_scan_of_public_ip_refused(self):
        with self.assertRaises(ValueError):
            scanner.scan_ports("8.8.8.8", [80])


class ScanTargetPinningTest(unittest.TestCase):
    def test_scan_connects_to_validated_address_not_hostname(self):
        """The hostname is resolved once, validated, and the connection
        goes to that address: DNS cannot change its answer between the
        check and the connect."""
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                      ("127.0.0.1", 0))]
        connected = []

        class FakeConn:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                pass

            def recv(self, size):
                raise socket.timeout()

        def fake_create_connection(addr, timeout=None):
            connected.append(addr)
            return FakeConn()

        with mock.patch.object(socket, "getaddrinfo",
                               return_value=fake_info), \
             mock.patch.object(socket, "create_connection",
                               side_effect=fake_create_connection):
            results = scanner.scan_ports("lab.test", [80])
        self.assertEqual(connected, [("127.0.0.1", 80)])
        self.assertEqual(results[0]["state"], "open")


if __name__ == "__main__":
    unittest.main()
