import contextlib
import io
import json
import socket
import unittest

from netlab.cli import main


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class PacketCommandTest(unittest.TestCase):
    def test_decodes_built_packet(self):
        code, out, _ = run_cli(["packet", "--flags", "SYN,ACK"])
        self.assertEqual(code, 0)
        self.assertIn("192.0.2.10", out)
        self.assertIn("198.51.100.7", out)
        self.assertIn("SYN,ACK", out)
        self.assertIn("checksum       valid", out)
        self.assertIn("open port", out)  # the SYN,ACK teaching note

    def test_payload_echoed(self):
        code, out, _ = run_cli(["packet", "--flags", "PSH,ACK",
                                "--payload", "hi"])
        self.assertEqual(code, 0)
        self.assertIn("'hi'", out)

    def test_unknown_flag_rejected(self):
        code, _, err = run_cli(["packet", "--flags", "BOGUS"])
        self.assertEqual(code, 2)
        self.assertIn("unknown TCP flag", err)

    def test_bad_ip_rejected(self):
        code, _, err = run_cli(["packet", "--src", "999.1.1.1"])
        self.assertEqual(code, 2)


class ScanCommandTest(unittest.TestCase):
    def test_refuses_public_target(self):
        code, out, err = run_cli(["scan", "--target", "8.8.8.8",
                                  "--ports", "80"])
        self.assertEqual(code, 2)
        self.assertIn("loopback", err)
        self.assertEqual(out, "")

    def test_json_output_against_live_server(self):
        from netlab.server import LabServer
        port = free_port()
        srv = LabServer(services=[{"port": port, "service": "ssh",
                                   "banner": "SSH-2.0-test\r\n"}],
                        log=lambda msg: None)
        srv.start()
        try:
            code, out, _ = run_cli(["scan", "--ports", str(port), "--json"])
        finally:
            srv.stop()
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["results"][0]["port"], port)
        self.assertEqual(data["results"][0]["state"], "open")
        self.assertEqual(data["results"][0]["banner"], "SSH-2.0-test")

    def test_text_output_against_live_server(self):
        from netlab.server import LabServer
        open_port, closed_port = free_port(), free_port()
        srv = LabServer(services=[{"port": open_port, "service": "ftp",
                                   "banner": "220 x\r\n"}],
                        log=lambda msg: None)
        srv.start()
        try:
            code, out, _ = run_cli(
                ["scan", "--ports", "%d,%d" % (open_port, closed_port)])
        finally:
            srv.stop()
        self.assertEqual(code, 0)
        self.assertIn("PORT", out)
        self.assertIn("1 open, 1 closed", out)

    def test_bad_port_spec_rejected(self):
        code, _, err = run_cli(["scan", "--ports", "not-a-port"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
