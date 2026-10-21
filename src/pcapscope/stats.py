"""Traffic summary: volumes, protocol mix, top talkers, conversations and DNS."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .decode import Packet

WELL_KNOWN_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 853: "dns-over-tls",
    1900: "ssdp", 3306: "mysql", 3389: "rdp", 5353: "mdns", 5355: "llmnr",
    8080: "http-alt",
}


@dataclass(slots=True)
class TrafficStats:
    packets: int = 0
    bytes: int = 0
    first: float | None = None
    last: float | None = None
    decode_errors: int = 0
    protocols: Counter = field(default_factory=Counter)
    talkers: Counter = field(default_factory=Counter)          # bytes sent per source
    conversations: Counter = field(default_factory=Counter)    # bytes per (a, b, proto, service port)
    services: Counter = field(default_factory=Counter)         # packets per (proto, service port)
    dns_queries: Counter = field(default_factory=Counter)
    errors: Counter = field(default_factory=Counter)

    def observe(self, pkt: Packet) -> None:
        self.packets += 1
        self.bytes += pkt.wire_len
        if pkt.timestamp:
            self.first = pkt.timestamp if self.first is None else min(self.first, pkt.timestamp)
            self.last = pkt.timestamp if self.last is None else max(self.last, pkt.timestamp)
        if pkt.error:
            self.decode_errors += 1
            self.errors[pkt.error] += 1

        layer = pkt.transport or pkt.network or "other"
        if pkt.dns is not None:
            layer = "dns"
        self.protocols[layer] += 1

        if pkt.src is None:
            return
        self.talkers[pkt.src] += pkt.wire_len
        if pkt.sport is not None:
            service = min(pkt.sport, pkt.dport)
            a, b = sorted((pkt.src, pkt.dst))
            self.conversations[(a, b, pkt.transport, service)] += pkt.wire_len
            self.services[(pkt.transport, service)] += 1
        if pkt.dns is not None and not pkt.dns.is_response:
            for name, _ in pkt.dns.questions:
                self.dns_queries[name.lower()] += 1

    @property
    def duration(self) -> float:
        if self.first is None or self.last is None:
            return 0.0
        return self.last - self.first


def service_name(proto: str | None, port: int) -> str:
    name = WELL_KNOWN_SERVICES.get(port)
    return f"{proto}/{port} ({name})" if name else f"{proto}/{port}"
