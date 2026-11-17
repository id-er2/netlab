"""Build and parse IPv4 and TCP headers.

Pure byte work with struct: no sockets, no network. This module is the
"packet journey" half of the lab - it shows what is actually inside the
headers that the other half sends on 127.0.0.1.
"""

import struct

IPPROTO_TCP = 6

TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

FLAG_VALUES = {name: bit for bit, name in TCP_FLAGS}


class PacketError(ValueError):
    """Raised when bytes cannot be parsed as the expected header."""


def ip_to_bytes(ip):
    """Dotted-quad string to 4 bytes. Raises PacketError on bad input."""
    parts = str(ip).split(".")
    if len(parts) != 4:
        raise PacketError("not an IPv4 address: %r" % (ip,))
    nums = []
    for part in parts:
        if not part.isdigit():
            raise PacketError("not an IPv4 address: %r" % (ip,))
        num = int(part)
        if num > 255:
            raise PacketError("not an IPv4 address: %r" % (ip,))
        nums.append(num)
    return bytes(nums)


def ip_from_bytes(raw):
    """4 bytes to dotted-quad string."""
    if len(raw) != 4:
        raise PacketError("IPv4 address must be 4 bytes")
    return ".".join(str(b) for b in raw)


def checksum(data):
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def flags_to_bits(names):
    """['SYN', 'ACK'] -> 0x12. Raises PacketError on an unknown flag."""
    bits = 0
    for name in names:
        key = name.strip().upper()
        if key not in FLAG_VALUES:
            raise PacketError("unknown TCP flag: %r" % (name,))
        bits |= FLAG_VALUES[key]
    return bits


def bits_to_flags(bits):
    """0x12 -> ['SYN', 'ACK'] (canonical order)."""
    return [name for bit, name in TCP_FLAGS if bits & bit]


def build_ipv4_header(src_ip, dst_ip, payload_length, protocol=IPPROTO_TCP,
                      ttl=64, identification=0):
    """20-byte IPv4 header with a valid checksum."""
    if not 0 <= payload_length <= 65515:
        raise PacketError("payload too large for one IPv4 packet")
    ver_ihl = (4 << 4) | 5
    total_length = 20 + payload_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_length, identification & 0xFFFF, 0,
        ttl & 0xFF, protocol & 0xFF, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    check = checksum(header)
    return header[:10] + struct.pack("!H", check) + header[12:]


def parse_ipv4_header(data):
    """Parse an IPv4 header. Returns a dict with a 'payload' entry."""
    if len(data) < 20:
        raise PacketError("need at least 20 bytes for an IPv4 header")
    (ver_ihl, _tos, total_length, identification, _frag, ttl, protocol,
     _check, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    if version != 4:
        raise PacketError("not an IPv4 packet (version %d)" % version)
    if ihl < 5:
        raise PacketError("invalid IPv4 header length %d" % ihl)
    header_length = ihl * 4
    if len(data) < header_length:
        raise PacketError("truncated IPv4 header")
    if checksum(data[:header_length]) != 0:
        raise PacketError("bad IPv4 checksum")
    end = total_length if 20 <= total_length <= len(data) else len(data)
    return {
        "version": version,
        "header_length": header_length,
        "total_length": total_length,
        "identification": identification,
        "ttl": ttl,
        "protocol": protocol,
        "src": ip_from_bytes(src),
        "dst": ip_from_bytes(dst),
        "payload": data[header_length:end],
    }


def build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq=0, ack=0,
                      flags=("SYN",), window=64240, payload=b""):
    """TCP segment (header + payload) with a valid checksum.

    src_ip/dst_ip are needed for the pseudo-header checksum, exactly as in
    a real stack. flags is a list of names ('SYN', 'ACK', ...) or an int.
    """
    flag_bits = flags if isinstance(flags, int) else flags_to_bits(flags)
    offset_reserved = 5 << 4  # 5 * 4 = 20 byte header, no options
    header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        offset_reserved, flag_bits, window & 0xFFFF, 0, 0,
    )
    pseudo = (ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)
              + struct.pack("!BBH", 0, IPPROTO_TCP, len(header) + len(payload)))
    check = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", check) + header[18:]
    return header + payload


def parse_tcp_segment(data, src_ip, dst_ip):
    """Parse a TCP segment and verify its checksum."""
    if len(data) < 20:
        raise PacketError("need at least 20 bytes for a TCP segment")
    (src_port, dst_port, seq, ack, offset_reserved, flag_bits, window,
     _check, _urg) = struct.unpack("!HHIIBBHHH", data[:20])
    header_length = (offset_reserved >> 4) * 4
    if header_length < 20 or len(data) < header_length:
        raise PacketError("truncated TCP header")
    pseudo = (ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)
              + struct.pack("!BBH", 0, IPPROTO_TCP, len(data)))
    if checksum(pseudo + data) != 0:
        raise PacketError("bad TCP checksum")
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "header_length": header_length,
        "flags": bits_to_flags(flag_bits),
        "flags_bits": flag_bits,
        "window": window,
        "payload": data[header_length:],
    }
