"""Loopback-only demo services with port-scan detection.

Run this in one terminal and scan it from another to see both sides of a
port scan: what the scanner learns, and what the defender can notice.
"""

import socket
import threading
import time
from collections import defaultdict, deque

from .scanner import require_loopback

# At most this many connections are handled at once; extra connections
# wait at the accept loop instead of spawning more threads.
MAX_HANDLER_THREADS = 32

# Unprivileged ports impersonating the classic services, so the lab works
# without root. ftp/ssh/smtp send a banner on connect, like the real
# things; http stays quiet until it gets a request, like the real thing.
DEFAULT_SERVICES = [
    {"port": 9021, "service": "ftp",
     "banner": "220 netlab ftpd ready\r\n"},
    {"port": 9022, "service": "ssh",
     "banner": "SSH-2.0-OpenSSH_9.6\r\n"},
    {"port": 9025, "service": "smtp",
     "banner": "220 netlab ESMTP ready\r\n"},
    {"port": 9080, "service": "http", "banner": ""},
    {"port": 9306, "service": "mysql",
     "banner": "5.7.44-netlab\r\n"},
]

HTTP_REPLY = (b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
              b"Content-Length: 14\r\n\r\nnetlab alive.\n")


class ScanDetector:
    """Flags one source touching many distinct ports in a short window.

    A normal client uses one or two ports; a scanner walks through many.
    That difference is the whole heuristic.
    """

    def __init__(self, threshold=4, window=10.0):
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        self.threshold = threshold
        self.window = window
        self._events = defaultdict(deque)  # source -> deque of (ts, port)
        self.alerts = []

    def record(self, source, port, now=None):
        """Record one connection. Returns an alert string, or None."""
        if now is None:
            now = time.monotonic()
        events = self._events[source]
        events.append((now, port))
        while events and now - events[0][0] > self.window:
            events.popleft()
        distinct = {p for _, p in events}
        if len(distinct) >= self.threshold:
            alert = ("possible port scan from %s: %d distinct ports "
                     "in %gs" % (source, len(distinct), self.window))
            self.alerts.append(alert)
            events.clear()  # re-arm: one alert per burst
            return alert
        return None


class LabServer:
    """Serves the demo services on a loopback address.

    Connection handlers run in threads, but their number is bounded by
    MAX_HANDLER_THREADS: a fast connect flood (for example a full-range
    port scan against the lab) queues at the accept loop instead of
    spawning one thread per connection until the machine runs out.
    """

    def __init__(self, host="127.0.0.1", services=None, detector=None,
                 log=None, max_handler_threads=MAX_HANDLER_THREADS):
        addrs = require_loopback(host)
        if not isinstance(max_handler_threads, int) or max_handler_threads < 1:
            raise ValueError("max_handler_threads must be a positive integer")
        self.host = next((a for a in addrs if ":" not in a), addrs[0])
        self._family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self.services = (services if services is not None
                         else list(DEFAULT_SERVICES))
        self.detector = detector if detector is not None else ScanDetector()
        self.log = log if log is not None else (
            lambda msg: print(msg, flush=True))
        self._sockets = []
        self._threads = []
        self._stop = threading.Event()
        self._handler_slots = threading.BoundedSemaphore(max_handler_threads)

    def start(self):
        for svc in self.services:
            sock = socket.socket(self._family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, svc["port"]))
            sock.listen(16)
            sock.settimeout(0.5)
            self._sockets.append(sock)
            thread = threading.Thread(
                target=self._accept_loop, args=(sock, svc), daemon=True)
            thread.start()
            self._threads.append(thread)
        self.log("netlab serving %d demo services on %s (ports %s)"
                 % (len(self.services), self.host,
                    ", ".join(str(s["port"]) for s in self.services)))

    def _accept_loop(self, sock, svc):
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Block until a handler slot frees: concurrency stays bounded
            # and every accepted connection is still served and recorded.
            while not self._handler_slots.acquire(timeout=0.1):
                if self._stop.is_set():
                    conn.close()
                    return
            if self._stop.is_set():
                self._handler_slots.release()
                conn.close()
                return
            try:
                threading.Thread(target=self._handle_guarded,
                                 args=(conn, addr, svc),
                                 daemon=True).start()
            except Exception:
                self._handler_slots.release()
                conn.close()
                raise

    def _handle_guarded(self, conn, addr, svc):
        try:
            self._handle(conn, addr, svc)
        finally:
            self._handler_slots.release()

    def _handle(self, conn, addr, svc):
        source = addr[0]
        stamp = time.strftime("%H:%M:%S")
        self.log("%s connection %s:%d -> :%d (%s)"
                 % (stamp, source, addr[1], svc["port"], svc["service"]))
        alert = self.detector.record(source, svc["port"])
        if alert:
            self.log("ALERT: " + alert)
        try:
            conn.settimeout(1.0)
            banner = svc.get("banner", "")
            if banner:
                conn.sendall(banner.encode("utf-8"))
            else:
                # http-style: wait for a request, then answer
                try:
                    conn.recv(1024)
                    conn.sendall(HTTP_REPLY)
                except (socket.timeout, OSError):
                    pass
            time.sleep(0.05)  # give the peer a moment to read
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=1.0)

    def serve_forever(self):
        self.start()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
