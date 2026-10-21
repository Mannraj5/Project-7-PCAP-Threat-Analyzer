"""Generate samples/demo.pcapng: a short synthetic incident on a small office LAN.

The lab captures in Project 2 cover scanning, exploitation and C2.  This
capture exercises the remaining detectors - DNS tunnelling, ARP spoofing,
cleartext credentials and beaconing - against a background of ordinary
traffic, so every rule can be seen firing from a fresh clone.

Every packet is built byte by byte with pcapscope.craft (valid checksums,
real header layouts) and the output is deterministic.

    python scripts/make_demo_capture.py
"""

from __future__ import annotations

import base64
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcapscope import craft  # noqa: E402
from pcapscope.decode import TCP_ACK, TCP_SYN  # noqa: E402

GATEWAY, GATEWAY_MAC = "10.10.0.1", "02:10:00:00:00:01"
WORKSTATION, WORKSTATION_MAC = "10.10.0.23", "02:10:00:00:00:23"
LAPTOP, LAPTOP_MAC = "10.10.0.42", "02:10:00:00:00:42"
ATTACKER, ATTACKER_MAC = "10.10.0.66", "02:10:00:00:00:66"
FILESERVER = "10.10.0.5"
RESOLVER = "10.10.0.1"
C2_SERVER = "203.0.113.77"

START = 1_767_225_600.0  # 2026-01-01 00:00:00 UTC


def build() -> list[tuple[float, bytes]]:
    rng = random.Random(20260101)
    frames: list[tuple[float, bytes]] = []

    def at(offset: float, frame: bytes) -> None:
        frames.append((START + offset, frame))

    # Background: ordinary DNS lookups and HTTPS sessions from two hosts.
    for i in range(120):
        host = (WORKSTATION, LAPTOP)[i % 2]
        name = rng.choice(["www.microsoft.com", "outlook.office365.com", "github.com",
                           "teams.microsoft.com", "www.deakin.edu.au", "pypi.org"])
        t = i * 4.5 + rng.random()
        at(t, craft.dns_frame(host, RESOLVER, name, sport=50000 + i))
        at(t + 0.05, craft.syn_frame(host, f"198.51.100.{rng.randint(2, 250)}", 52000 + i, 443))

    # 1. The attacker poisons the workstation's ARP cache to sit in the middle.
    at(30.0, craft.arp_frame(2, GATEWAY_MAC, GATEWAY, WORKSTATION))
    for k in range(6):
        at(60.0 + 10 * k, craft.arp_frame(2, ATTACKER_MAC, GATEWAY, WORKSTATION))

    # 2. ...and so sees the workstation log in to the file server over FTP and an
    #    intranet page over HTTP Basic auth.
    ftp = [(TCP_SYN, b""), (TCP_ACK, b"USER svc_backup\r\n"), (TCP_ACK, b"PASS Spring2026!\r\n")]
    for k, (flags, payload) in enumerate(ftp):
        at(120.0 + k * 0.2, craft.tcp_frame(WORKSTATION, FILESERVER, 49812, 21, flags, payload))
    token = base64.b64encode(b"jsmith:Welcome123").decode()
    http = f"GET /admin/ HTTP/1.1\r\nHost: intranet.local\r\nAuthorization: Basic {token}\r\n\r\n"
    at(150.0, craft.tcp_frame(WORKSTATION, FILESERVER, 49820, 80, payload=http.encode()))

    # 3. Malware on the laptop beacons to its C2 server every 30 s (+/- 1 s jitter).
    for k in range(14):
        at(200.0 + 30 * k + rng.uniform(-1, 1), craft.syn_frame(LAPTOP, C2_SERVER, 53000 + k, 8443))

    # 4. ...and exfiltrates a file through DNS: base32 chunks under one domain.
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for k in range(60):
        chunk = "".join(rng.choice(alphabet) for _ in range(56))
        at(400.0 + k * 0.4, craft.dns_frame(LAPTOP, RESOLVER, f"{chunk}.{k:04x}.x.cdn-telemetry.net",
                                            sport=54000 + k))

    frames.sort(key=lambda f: f[0])
    return frames


def main() -> None:
    out = ROOT / "samples" / "demo.pcapng"
    out.parent.mkdir(exist_ok=True)
    frames = build()
    craft.write_pcapng(out, frames)
    print(f"wrote {len(frames)} packets to {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
