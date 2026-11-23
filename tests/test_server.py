import socket
import threading
import time
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


class HandlerThreadBoundTest(unittest.TestCase):
    def test_handler_threads_are_bounded_and_none_dropped(self):
        port = free_port()
        active = 0
        peak = 0
        done = 0
        lock = threading.Lock()
        srv = LabServer(
            services=[{"port": port, "service": "http", "banner": ""}],
            log=lambda msg: None, max_handler_threads=2)
        orig_handle = srv._handle

        def counting(conn, addr, svc):
            nonlocal active, peak, done
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                orig_handle(conn, addr, svc)
            finally:
                with lock:
                    active -= 1
                    done += 1

        srv._handle = counting
        srv.start()
        try:
            # Six idle clients: each handler waits out its 1s recv
            # timeout, so without a bound six threads would pile up.
            conns = [socket.create_connection(("127.0.0.1", port), timeout=5)
                     for _ in range(6)]
            deadline = time.time() + 15
            while time.time() < deadline:
                with lock:
                    if done == 6:
                        break
                time.sleep(0.05)
            for conn in conns:
                conn.close()
        finally:
            srv.stop()
        self.assertEqual(done, 6)  # every connection still served
        self.assertLessEqual(peak, 2)


if __name__ == "__main__":
    unittest.main()
