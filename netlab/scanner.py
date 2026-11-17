"""Loopback-only TCP connect scanner.

Every public entry point calls require_loopback() before touching the
network, so this scanner cannot be pointed at anything except this
machine. That is a deliberate design limit, not a missing feature.
"""

import ipaddress
import socket
import time

# The usual suspects, matching the quick-review sheet in the networking
# notes this lab accompanies.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 8080: "http-alt",
}


def require_loopback(host):
    """Resolve host and raise ValueError unless every address is loopback."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("cannot resolve target %r: %s" % (host, exc))
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        raise ValueError("cannot resolve target %r" % (host,))
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            raise ValueError("cannot parse resolved address %r" % (addr,))
        if not ip.is_loopback:
            raise ValueError(
                "refusing non-loopback target %r (%s): "
                "this lab only runs on this machine" % (host, addr))
    return addrs


def parse_port_spec(spec):
    """'9021,9030-9032' -> [9021, 9030, 9031, 9032] (sorted, unique)."""
    ports = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError("bad port range %r" % part)
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("no ports given")
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError("port out of range: %d" % port)
    return sorted(ports)


def scan_ports(host, ports, timeout=1.0, banner_timeout=0.5, max_banner=64):
    """Connect-scan ports on a loopback host.

    Returns a list of dicts: port, state ('open'/'closed'), service,
    banner (if the service sent one) and latency_ms.
    """
    require_loopback(host)
    results = []
    for port in ports:
        started = time.monotonic()
        state = "closed"
        banner = ""
        try:
            with socket.create_connection((host, port), timeout=timeout) as conn:
                state = "open"
                conn.settimeout(banner_timeout)
                try:
                    data = conn.recv(max_banner)
                    banner = data.decode("utf-8", "replace").strip()
                except (socket.timeout, OSError):
                    pass
        except (ConnectionRefusedError, socket.timeout, OSError):
            state = "closed"
        latency = (time.monotonic() - started) * 1000.0
        results.append({
            "port": port,
            "state": state,
            "service": COMMON_PORTS.get(port, ""),
            "banner": banner,
            "latency_ms": round(latency, 1),
        })
    return results
