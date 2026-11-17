import socket
import unittest

from netlab.server import LabServer, ScanDetector


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class LabServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ftp_port = free_port()
        cls.http_port = free_port()
        cls.logs = []
        cls.server = LabServer(services=[
            {"port": cls.ftp_port, "service": "ftp",
             "banner": "220 test ftpd\r\n"},
            {"port": cls.http_port, "service": "http", "banner": ""},
        ], log=cls.logs.append)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_banner_service_sends_banner(self):
        with socket.create_connection(("127.0.0.1", self.ftp_port),
                                      timeout=2) as conn:
            data = conn.recv(64)
        self.assertEqual(data, b"220 test ftpd\r\n")

    def test_http_service_waits_for_request(self):
        with socket.create_connection(("127.0.0.1", self.http_port),
                                      timeout=2) as conn:
            conn.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                conn.recv(64)  # no banner before a request
            conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
            reply = conn.recv(256)
        self.assertIn(b"200 OK", reply)
        self.assertIn(b"netlab alive.", reply)

    def test_connections_are_logged(self):
        with socket.create_connection(("127.0.0.1", self.ftp_port),
                                      timeout=2):
            pass
        self.assertTrue(any(":%d (ftp)" % self.ftp_port in line
                            for line in self.logs))

    def test_non_loopback_bind_refused(self):
        with self.assertRaises(ValueError):
            LabServer(host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
