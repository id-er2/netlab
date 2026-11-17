import unittest

from netlab import packets


class ChecksumTest(unittest.TestCase):
    def test_rfc1071_example(self):
        # The worked example from RFC 1071: 0001 f203 f4f5 f6f7 -> 220d
        data = bytes([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7])
        self.assertEqual(packets.checksum(data), 0x220D)

    def test_odd_length_padded(self):
        even = packets.checksum(b"\x01\x02\x03\x00")
        odd = packets.checksum(b"\x01\x02\x03")
        self.assertEqual(even, odd)


class IpCodecTest(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(packets.ip_from_bytes(packets.ip_to_bytes(
            "192.0.2.10")), "192.0.2.10")

    def test_rejects_bad_addresses(self):
        for bad in ["256.1.1.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", ""]:
            with self.assertRaises(packets.PacketError):
                packets.ip_to_bytes(bad)


class FlagsTest(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(packets.bits_to_flags(
            packets.flags_to_bits(["SYN", "ACK"])), ["SYN", "ACK"])

    def test_unknown_flag_rejected(self):
        with self.assertRaises(packets.PacketError):
            packets.flags_to_bits(["SYN", "NOPE"])

    def test_empty_flags(self):
        self.assertEqual(packets.flags_to_bits([]), 0)
        self.assertEqual(packets.bits_to_flags(0), [])


class IPv4Test(unittest.TestCase):
    def test_build_and_parse(self):
        header = packets.build_ipv4_header(
            "192.0.2.1", "198.51.100.2", payload_length=20, ttl=42,
            identification=7)
        self.assertEqual(len(header), 20)
        info = packets.parse_ipv4_header(header)
        self.assertEqual(info["src"], "192.0.2.1")
        self.assertEqual(info["dst"], "198.51.100.2")
        self.assertEqual(info["ttl"], 42)
        self.assertEqual(info["identification"], 7)
        self.assertEqual(info["protocol"], packets.IPPROTO_TCP)
        self.assertEqual(info["total_length"], 40)

    def test_corrupted_header_rejected(self):
        header = bytearray(packets.build_ipv4_header(
            "192.0.2.1", "198.51.100.2", payload_length=0))
        header[0] ^= 0xFF
        with self.assertRaises(packets.PacketError):
            packets.parse_ipv4_header(bytes(header))

    def test_short_input_rejected(self):
        with self.assertRaises(packets.PacketError):
            packets.parse_ipv4_header(b"\x45" + b"\x00" * 10)


class TcpTest(unittest.TestCase):
    def test_build_and_parse(self):
        seg = packets.build_tcp_segment(
            "192.0.2.1", "198.51.100.2", 51000, 22,
            seq=12345, ack=0, flags=["SYN"], window=1000)
        info = packets.parse_tcp_segment(seg, "192.0.2.1", "198.51.100.2")
        self.assertEqual(info["src_port"], 51000)
        self.assertEqual(info["dst_port"], 22)
        self.assertEqual(info["seq"], 12345)
        self.assertEqual(info["flags"], ["SYN"])
        self.assertEqual(info["window"], 1000)
        self.assertEqual(info["payload"], b"")

    def test_flags_and_payload_survive(self):
        seg = packets.build_tcp_segment(
            "10.0.0.1", "10.0.0.2", 8080, 80,
            flags=["PSH", "ACK"], payload=b"hello")
        info = packets.parse_tcp_segment(seg, "10.0.0.1", "10.0.0.2")
        self.assertEqual(info["flags"], ["PSH", "ACK"])
        self.assertEqual(info["payload"], b"hello")

    def test_corrupted_segment_rejected(self):
        seg = bytearray(packets.build_tcp_segment(
            "10.0.0.1", "10.0.0.2", 1, 2))
        seg[3] ^= 0xFF
        with self.assertRaises(packets.PacketError):
            packets.parse_tcp_segment(bytes(seg), "10.0.0.1", "10.0.0.2")

    def test_wrong_addresses_rejected(self):
        seg = packets.build_tcp_segment("10.0.0.1", "10.0.0.2", 1, 2)
        with self.assertRaises(packets.PacketError):
            packets.parse_tcp_segment(seg, "10.0.0.9", "10.0.0.2")


class FullPacketTest(unittest.TestCase):
    def test_ipv4_wrapping_tcp_round_trip(self):
        seg = packets.build_tcp_segment(
            "192.0.2.10", "198.51.100.7", 51000, 22, flags=["SYN", "ACK"])
        packet = (packets.build_ipv4_header(
                      "192.0.2.10", "198.51.100.7", len(seg)) + seg)
        ip_info = packets.parse_ipv4_header(packet)
        tcp_info = packets.parse_tcp_segment(
            ip_info["payload"], ip_info["src"], ip_info["dst"])
        self.assertEqual(tcp_info["flags"], ["SYN", "ACK"])
        self.assertEqual(ip_info["total_length"], 40)


if __name__ == "__main__":
    unittest.main()
