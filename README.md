# netlab

A small networking lab that runs entirely on your own machine. It shows
one technique - a TCP port scan - from both sides: what the scanner
learns, and what the defender can notice. A third command builds and
decodes raw IPv4/TCP headers offline, to show what is inside the packets.

Written as a companion to my Arabic networking notes, which go from the
journey of a packet to the basics of protection.

Python 3.9+, standard library only. No dependencies, no installation.

## Safety

Everything is bound to 127.0.0.1 by design:

- `scan` resolves the target first and refuses anything that is not a
  loopback address. There is no flag to override this.
- `serve` binds demo services to 127.0.0.1 only.
- `packet` does no network I/O at all.

## Usage

Terminal 1 - run the demo lab (ftp, ssh, smtp, http and mysql lookalikes
on high ports, no root needed). The http port answers no banner because,
like the real thing, it waits for a request:

```
$ python3 -m netlab serve
netlab serving 5 demo services on 127.0.0.1 (ports 9021, 9022, 9025, 9080, 9306)
demo lab running - scan it from another terminal with: python3 -m netlab scan
detection: 4 distinct ports within 10s from one source raises an alert; Ctrl+C to stop
```

Terminal 2 - scan it:

```
$ python3 -m netlab scan
PORT    STATE   SERVICE   BANNER
9021    open    -         220 netlab ftpd ready
9022    open    -         SSH-2.0-OpenSSH_9.6
9025    open    -         220 netlab ESMTP ready
9080    open    -
9306   open    -         5.7.44-netlab

scanned 5 ports on 127.0.0.1 in 0.5s: 5 open, 0 closed
```

Back in terminal 1, the defender's view:

```
15:04:22 connection 127.0.0.1:54012 -> :9021 (ftp)
15:04:22 connection 127.0.0.1:54013 -> :9022 (ssh)
15:04:22 connection 127.0.0.1:54014 -> :9025 (smtp)
15:04:22 connection 127.0.0.1:54015 -> :9080 (http)
ALERT: possible port scan from 127.0.0.1: 4 distinct ports in 10s
```

That alert is the point of the lab: a normal client uses one or two
ports, a scanner walks through many, and even a few lines of code can
tell the difference.

`scan --json` gives machine-readable output. `scan --ports 9000-9100`
takes ranges.

### The packet command (offline)

```
$ python3 -m netlab packet --flags SYN --dport 22
built a 40-byte IPv4+TCP packet and parsed it back (no network involved)

IPv4 header (20 bytes):
  src            192.0.2.10
  dst            198.51.100.7
  total_length   40
  ttl            64
  protocol       6 (TCP)
  checksum       valid

TCP segment (20 bytes):
  src_port       51000
  dst_port       22
  seq            0
  ack            0
  flags          SYN (0x02)
  window         64240
  checksum       valid

note: a lone SYN starts a connection; every port scan begins here
```

The command builds the bytes with `struct`, computes both checksums the
way a real stack does, then parses the packet back to prove the layout.
Try `--flags FIN` for the flag combination a FIN scan uses, or
`--flags SYN,ACK` for the answer an open port gives.

## What it demonstrates

- The TCP handshake: what a SYN gets back from an open port (SYN,ACK)
  versus a closed one (RST,ACK).
- Banner grabbing: ftp/ssh/smtp announce themselves on connect; http
  stays silent until you ask. The demo services behave the same way.
- Scan detection: counting distinct ports per source in a time window,
  the idea behind real network monitoring.
- IPv4 and TCP header layout and the internet checksum (RFC 1071),
  verified by round-trip parsing.

## Tests

```
python3 -m unittest discover -s tests -t . -v
```

The suite covers the checksum against the RFC 1071 worked example,
header round-trips, corrupted-packet rejection, the detector logic, a
live serve/scan loop on ephemeral loopback ports, and a check that the
scanner refuses a public address before creating any socket.

## Limits

- Connect scans only. SYN/FIN scans need raw sockets and root; the flag
  combinations are explained by `packet`, not sent.
- The detector is a teaching heuristic. Real detection uses more signals
  and tuned thresholds.
- Demo services imitate banners; they are not real ftp/ssh/smtp servers.
- The port-to-service table is a small built-in list, not a full
  services database.

## License

MIT - see [LICENSE](LICENSE).
