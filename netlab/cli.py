"""Command-line interface for netlab."""

import argparse
import json
import sys
import time

from . import packets, scanner, server

# One-line notes for the flag combinations a beginner meets first.
FLAG_NOTES = {
    ("SYN",): "a lone SYN starts a connection; every port scan begins here",
    ("SYN", "ACK"): "the answer from an open port (step 2 of the handshake)",
    ("ACK", "RST"): "the answer from a closed port",
    ("RST",): "connection reset: the conversation is over",
    ("FIN",): "FIN with no ACK is what a FIN scan sends; closed ports answer RST",
    ("FIN", "ACK"): "polite teardown of an established connection",
}

DEFAULT_SCAN_PORTS = "9021,9022,9025,9080,9306"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netlab",
        description="A small loopback-only networking lab: demo services, "
                    "a connect scanner, scan detection, and packet headers "
                    "decoded offline. Nothing here leaves this machine.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser(
        "serve", help="run demo services on 127.0.0.1 and watch for scans")
    p_serve.add_argument("--threshold", type=int, default=4,
                         help="distinct ports that trigger a scan alert "
                              "(default: 4)")
    p_serve.add_argument("--window", type=float, default=10.0,
                         help="detection window in seconds (default: 10)")

    p_scan = sub.add_parser(
        "scan", help="connect-scan ports on this machine")
    p_scan.add_argument("--target", default="127.0.0.1",
                        help="loopback targets only (default: 127.0.0.1)")
    p_scan.add_argument("--ports", default=DEFAULT_SCAN_PORTS,
                        help="ports: list and/or ranges, e.g. "
                             "9000-9100,9306 (default: the demo services)")
    p_scan.add_argument("--timeout", type=float, default=1.0,
                        help="connect timeout in seconds (default: 1)")
    p_scan.add_argument("--json", action="store_true",
                        help="machine-readable output")

    p_packet = sub.add_parser(
        "packet", help="build a TCP/IPv4 packet and decode it (offline)")
    p_packet.add_argument("--flags", default="SYN",
                          help="comma-separated TCP flags, e.g. SYN,ACK")
    p_packet.add_argument("--src", default="192.0.2.10",
                          help="source IPv4 (default: 192.0.2.10, TEST-NET-1)")
    p_packet.add_argument("--dst", default="198.51.100.7",
                          help="destination IPv4 (default: 198.51.100.7, "
                               "TEST-NET-2)")
    p_packet.add_argument("--sport", type=int, default=51000,
                          help="source port (default: 51000)")
    p_packet.add_argument("--dport", type=int, default=22,
                          help="destination port (default: 22)")
    p_packet.add_argument("--payload", default="",
                          help="payload text (default: empty)")
    return parser


def _cmd_serve(args):
    detector = server.ScanDetector(threshold=args.threshold,
                                   window=args.window)
    srv = server.LabServer(detector=detector)
    srv.start()
    print("demo lab running - scan it from another terminal with: "
          "python3 -m netlab scan")
    print("detection: %d distinct ports within %gs from one source "
          "raises an alert; Ctrl+C to stop" % (args.threshold, args.window))
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    return 0


def _cmd_scan(args):
    ports = scanner.parse_port_spec(args.ports)
    scanner.require_loopback(args.target)
    started = time.monotonic()
    results = scanner.scan_ports(args.target, ports, timeout=args.timeout)
    elapsed = time.monotonic() - started
    if args.json:
        print(json.dumps({"target": args.target, "results": results},
                         indent=2))
        return 0
    print("%-7s %-7s %-9s %s" % ("PORT", "STATE", "SERVICE", "BANNER"))
    open_count = 0
    for res in results:
        if res["state"] == "open":
            open_count += 1
        print("%-7d %-7s %-9s %s" % (res["port"], res["state"],
                                     res["service"] or "-",
                                     res["banner"] or ""))
    print("\nscanned %d ports on %s in %.1fs: %d open, %d closed"
          % (len(results), args.target, elapsed, open_count,
             len(results) - open_count))
    return 0


def _cmd_packet(args):
    flag_names = [f.strip().upper() for f in args.flags.split(",") if f.strip()]
    payload = args.payload.encode("utf-8")
    segment = packets.build_tcp_segment(
        args.src, args.dst, args.sport, args.dport,
        flags=flag_names, payload=payload)
    datagram = (packets.build_ipv4_header(args.src, args.dst, len(segment))
                + segment)
    ip_info = packets.parse_ipv4_header(datagram)
    tcp_info = packets.parse_tcp_segment(ip_info["payload"],
                                         args.src, args.dst)
    print("built a %d-byte IPv4+TCP packet and parsed it back "
          "(no network involved)\n" % len(datagram))
    print("IPv4 header (%d bytes):" % ip_info["header_length"])
    print("  src            %s" % ip_info["src"])
    print("  dst            %s" % ip_info["dst"])
    print("  total_length   %d" % ip_info["total_length"])
    print("  ttl            %d" % ip_info["ttl"])
    print("  protocol       %d (TCP)" % ip_info["protocol"])
    print("  checksum       valid")
    print("\nTCP segment (%d bytes):" % tcp_info["header_length"])
    print("  src_port       %d" % tcp_info["src_port"])
    print("  dst_port       %d" % tcp_info["dst_port"])
    print("  seq            %d" % tcp_info["seq"])
    print("  ack            %d" % tcp_info["ack"])
    print("  flags          %s (0x%02x)"
          % (",".join(tcp_info["flags"]) or "(none)",
             tcp_info["flags_bits"]))
    print("  window         %d" % tcp_info["window"])
    print("  checksum       valid")
    if tcp_info["payload"]:
        print("  payload        %r" % tcp_info["payload"].decode(
            "utf-8", "replace"))
    note = FLAG_NOTES.get(tuple(tcp_info["flags"]))
    if note:
        print("\nnote: " + note)
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"serve": _cmd_serve, "scan": _cmd_scan, "packet": _cmd_packet}
    try:
        return handlers[args.command](args)
    except (ValueError, packets.PacketError) as exc:
        print("netlab: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
