"""Detectors that turn a stream of decoded packets into findings.

Each detector sees every packet once through :meth:`Detector.observe` and
reports at the end through :meth:`Detector.findings`.  Detectors keep only
aggregated state (sets, counters, timestamps), so memory grows with the
number of hosts and ports in the capture, not the number of packets.

Two kinds of finding are produced:

* ``threat``  - behaviour worth investigating (scans, C2, tunnelling, spoofing,
  credentials in the clear).
* ``sensor``  - properties of the capture itself that silently degrade other
  tools' analysis (checksum offload, oversized frames, truncation).
"""

from __future__ import annotations

import functools
import ipaddress
import math
import statistics
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .decode import IPPROTO_ICMP, IPPROTO_ICMPV6, TCP_ACK, TCP_SYN, Packet

SEVERITIES = ("info", "low", "medium", "high")

# Default ports of common offensive tooling and backdoors.  A connection to one
# of these is not proof of compromise, which is why it is reported at "medium"
# unless the session also looks interactive.
SUSPICIOUS_PORTS = {
    1337: "common backdoor port",
    4444: "Metasploit default handler",
    4445: "Metasploit alternate handler",
    5555: "common reverse-shell / ADB port",
    6666: "common IRC botnet / backdoor port",
    6667: "IRC (botnet C2)",
    31337: "Back Orifice / 'elite' backdoor port",
}


@dataclass(slots=True)
class Config:
    scan_min_ports: int = 25           # distinct ports probed on one host
    sweep_min_hosts: int = 15          # distinct hosts probed by one source
    beacon_min_events: int = 6         # connection attempts needed to judge periodicity
    beacon_max_jitter: float = 0.25    # coefficient of variation of the intervals
    dns_long_label: int = 40           # label length that suggests encoded data
    dns_min_entropy: float = 3.5       # bits/char of the subdomain part
    dns_min_unique_subdomains: int = 15
    mtu_frame: int = 1514              # largest standard Ethernet frame without FCS
    offload_min_ratio: float = 0.2     # share of a host's packets with bad checksums...
    offload_min_count: int = 100       # ...or this many, for hosts whose tools build their own
                                       # packets (nmap SYNs carry correct checksums and dilute the ratio)


@dataclass(slots=True)
class Finding:
    rule: str
    category: str                      # "threat" or "sensor"
    severity: str
    title: str
    summary: str
    src: str | None = None
    dst: str | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    frames: list[int] = field(default_factory=list)   # sample frame numbers for Wireshark
    evidence: dict = field(default_factory=dict)

    @property
    def severity_rank(self) -> int:
        return SEVERITIES.index(self.severity)


class Detector:
    rule = "base"

    def __init__(self, config: Config) -> None:
        self.config = config

    def observe(self, pkt: Packet) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def findings(self) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass(slots=True)
class _Window:
    first: float = math.inf
    last: float = -math.inf
    frames: list[int] = field(default_factory=list)

    def add(self, pkt: Packet, keep: int = 5) -> None:
        self.first = min(self.first, pkt.timestamp)
        self.last = max(self.last, pkt.timestamp)
        if len(self.frames) < keep and pkt.index not in self.frames:
            self.frames.append(pkt.index)


def _ip_sort_key(address: str) -> tuple[int, int]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return (9, 0)
    return (ip.version, int(ip))


# --------------------------------------------------------------------------- scans


class PortScanDetector(Detector):
    """Vertical TCP scans: one source sending bare SYNs to many ports of one host.

    Open ports are those that answered SYN-ACK, which separates a scan that
    found something from one that hit a firewall.
    """

    rule = "port-scan"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._probed: dict[tuple[str, str], set[int]] = defaultdict(set)
        self._open: dict[tuple[str, str], set[int]] = defaultdict(set)
        self._windows: dict[tuple[str, str], _Window] = defaultdict(_Window)

    def observe(self, pkt: Packet) -> None:
        if pkt.has_flags(TCP_SYN, without=TCP_ACK):
            key = (pkt.src, pkt.dst)
            self._probed[key].add(pkt.dport)
            self._windows[key].add(pkt)
        elif pkt.has_flags(TCP_SYN | TCP_ACK):
            self._open[(pkt.dst, pkt.src)].add(pkt.sport)

    def findings(self) -> list[Finding]:
        out = []
        for (src, dst), ports in self._probed.items():
            if len(ports) < self.config.scan_min_ports:
                continue
            window = self._windows[(src, dst)]
            open_ports = sorted(self._open[(src, dst)] & ports)
            duration = max(window.last - window.first, 1e-6)
            rate = len(ports) / duration
            severity = "high" if len(ports) >= 1000 else "medium"
            out.append(Finding(
                self.rule, "threat", severity,
                f"TCP port scan of {dst}",
                f"{src} sent SYN probes to {len(ports):,} distinct ports on {dst} "
                f"in {duration:.1f}s ({rate:,.0f} ports/s); {len(open_ports)} answered SYN-ACK.",
                src, dst, window.first, window.last, window.frames,
                {"ports_probed": len(ports), "open_ports": open_ports[:50],
                 "duration_s": round(duration, 3), "ports_per_second": round(rate, 1)},
            ))
        return out


@functools.lru_cache(maxsize=65536)
def same_subnet(a: str, b: str) -> bool:
    """True if both addresses share a /24 (IPv4) or /64 (IPv6)."""
    try:
        ip_a, ip_b = ipaddress.ip_address(a), ipaddress.ip_address(b)
    except ValueError:
        return False
    if ip_a.version != ip_b.version:
        return False
    prefix = 24 if ip_a.version == 4 else 64
    return ipaddress.ip_network(f"{a}/{prefix}", strict=False) == \
        ipaddress.ip_network(f"{b}/{prefix}", strict=False)


class HostSweepDetector(Detector):
    """Host discovery: one source probing many addresses (ARP, ICMP echo or SYN).

    ICMP and SYN probes only count when the target shares the source's subnet:
    a browser opening HTTPS connections to dozens of CDN addresses looks the
    same as a SYN sweep by volume, but it does not stay inside the local
    network.  The trade-off is that sweeps of *other* internal subnets are not
    reported by this rule.
    """

    rule = "host-sweep"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._targets: dict[tuple[str, str], set[str]] = defaultdict(set)
        self._windows: dict[tuple[str, str], _Window] = defaultdict(_Window)

    def observe(self, pkt: Packet) -> None:
        method = None
        if pkt.network == "arp" and pkt.arp_op == 1 and pkt.arp_sender_ip != pkt.arp_target_ip:
            method = "ARP"
        elif pkt.protocol == IPPROTO_ICMP and pkt.icmp_type == 8:
            method = "ICMP echo"
        elif pkt.protocol == IPPROTO_ICMPV6 and pkt.icmp_type == 128:
            method = "ICMPv6 echo"
        elif pkt.has_flags(TCP_SYN, without=TCP_ACK):
            method = "TCP SYN"
        if method is None or pkt.src is None:
            return
        if method != "ARP" and not same_subnet(pkt.src, pkt.dst):
            return
        key = (pkt.src, method)
        self._targets[key].add(pkt.dst)
        self._windows[key].add(pkt)

    def findings(self) -> list[Finding]:
        out = []
        for (src, method), targets in self._targets.items():
            if len(targets) < self.config.sweep_min_hosts:
                continue
            window = self._windows[(src, method)]
            out.append(Finding(
                self.rule, "threat", "medium",
                f"{method} host sweep from {src}",
                f"{src} probed {len(targets)} distinct addresses with {method} "
                f"over {window.last - window.first:.1f}s.",
                src, None, window.first, window.last, window.frames,
                {"method": method, "hosts_probed": len(targets),
                 "sample_targets": sorted(targets, key=_ip_sort_key)[:20]},
            ))
        return out


# ------------------------------------------------------------------- command & control


@dataclass(slots=True)
class _Session:
    syn_times: list[float] = field(default_factory=list)
    packets: int = 0
    bytes_to_dst: int = 0
    bytes_to_src: int = 0
    window: _Window = field(default_factory=_Window)


class C2Detector(Detector):
    """Command-and-control indicators on TCP.

    * connections to default ports of offensive tooling, sized by how much data
      actually flowed (a refused SYN is very different from an interactive shell);
    * beaconing: repeated connections to the same service at a regular interval.
    """

    rule = "c2"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        # Per service (client, server, server port): totals across all its connections.
        self._sessions: dict[tuple[str, str, int], _Session] = defaultdict(_Session)
        # Per connection (client, client port, server, server port), so that the
        # direction of each packet is decided by its full 4-tuple.  Keying on the
        # service alone mis-assigns traffic after a port scan, when a server
        # port happens to equal another connection's ephemeral client port.
        self._connections: set[tuple[str, int, str, int]] = set()

    def observe(self, pkt: Packet) -> None:
        if pkt.tcp_flags is None or pkt.src is None:
            return
        forward = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
        reverse = (pkt.dst, pkt.dport, pkt.src, pkt.sport)
        if forward in self._connections:
            conn, outbound = forward, True
        elif reverse in self._connections:
            conn, outbound = reverse, False
        elif pkt.has_flags(TCP_SYN, without=TCP_ACK) or pkt.dport < pkt.sport:
            # A SYN names the client; without one (capture started mid-session)
            # assume the lower port is the service.
            conn, outbound = forward, True
            self._connections.add(conn)
        else:
            conn, outbound = reverse, False
            self._connections.add(conn)

        session = self._sessions[(conn[0], conn[2], conn[3])]
        session.packets += 1
        session.window.add(pkt)
        if outbound:
            session.bytes_to_dst += len(pkt.payload)
        else:
            session.bytes_to_src += len(pkt.payload)
        if pkt.has_flags(TCP_SYN, without=TCP_ACK):
            session.syn_times.append(pkt.timestamp)

    def findings(self) -> list[Finding]:
        out = []
        for (client, server, port), session in self._sessions.items():
            out.extend(self._port_finding(client, server, port, session))
            out.extend(self._beacon_finding(client, server, port, session))
        return out

    def _port_finding(self, client: str, server: str, port: int, session: _Session) -> list[Finding]:
        reason = SUSPICIOUS_PORTS.get(port)
        if reason is None:
            return []
        payload = session.bytes_to_dst + session.bytes_to_src
        if payload == 0:
            return []
        severity = "high" if payload > 10_000 else "medium"
        w = session.window
        return [Finding(
            self.rule, "threat", severity,
            f"Session on port {port} ({reason})",
            f"{client} -> {server}:{port}, {session.packets} packets, "
            f"{session.bytes_to_dst:,} B sent / {session.bytes_to_src:,} B received "
            f"over {w.last - w.first:.1f}s.",
            client, server, w.first, w.last, w.frames,
            {"port": port, "reason": reason, "packets": session.packets,
             "bytes_client_to_server": session.bytes_to_dst,
             "bytes_server_to_client": session.bytes_to_src},
        )]

    def _beacon_finding(self, client: str, server: str, port: int, session: _Session) -> list[Finding]:
        times = sorted(session.syn_times)
        if len(times) < self.config.beacon_min_events:
            return []
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(intervals)
        if mean < 1.0:
            return []  # bursts of retries, not beaconing
        jitter = statistics.pstdev(intervals) / mean
        if jitter > self.config.beacon_max_jitter:
            return []
        w = session.window
        return [Finding(
            "beacon", "threat", "high" if jitter < 0.1 else "medium",
            f"Periodic connections to {server}:{port}",
            f"{client} opened {len(times)} connections to {server}:{port} every "
            f"{mean:.1f}s (jitter {jitter:.0%}).",
            client, server, w.first, w.last, w.frames,
            {"connections": len(times), "mean_interval_s": round(mean, 2),
             "jitter": round(jitter, 3)},
        )]


# --------------------------------------------------------------------------- SMB

_SMB1_MAGIC = b"\xffSMB"
_SMB1_SESSION_SETUP = 0x73
_SMB1_TRANS2 = 0x32
_TRANS2_SESSION_SETUP = 0x000E
_DOUBLEPULSAR_PING_MID = 0x41      # 65: multiplex ID used by DoublePulsar "ping"
_DOUBLEPULSAR_PRESENT_MID = 0x51   # 81: ping MID + 16, returned only by an infected host


class SmbExploitDetector(Detector):
    """SMBv1 abuse on TCP/445.

    * Trans2 SESSION_SETUP (subcommand 0x0e) is not used by legitimate clients;
      it is the DoublePulsar backdoor's control channel and is sent by MS17-010
      exploits (EternalBlue and the Metasploit modules) to check for the
      implant.  The reply's Multiplex ID says whether the implant answered.
    * A completed SMBv1 session setup is reported at low severity: SMBv1 has
      been deprecated since 2014 and most modern clients only offer it in the
      initial dialect negotiation.

    Offsets assume the 4-byte NetBIOS session header that precedes every SMB
    message on port 445.
    """

    rule = "smb-exploit"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._probes: dict[tuple[str, str], _Window] = defaultdict(_Window)
        self._probe_counts: Counter = Counter()
        self._v1_session_counts: Counter = Counter()
        self._probe_mids: dict[tuple[str, str], set[int]] = defaultdict(set)
        self._implant_replies: dict[tuple[str, str], int] = Counter()
        self._probe_replies: dict[tuple[str, str], int] = Counter()
        self._v1_sessions: dict[tuple[str, str], _Window] = defaultdict(_Window)

    def observe(self, pkt: Packet) -> None:
        if 445 not in (pkt.sport, pkt.dport) or pkt.tcp_flags is None:
            return
        data = pkt.payload
        if len(data) < 36 or data[4:8] != _SMB1_MAGIC:
            return
        command = data[8]
        (status,) = struct.unpack("<I", data[9:13])
        (mid,) = struct.unpack("<H", data[34:36])
        request = pkt.dport == 445
        key = (pkt.src, pkt.dst) if request else (pkt.dst, pkt.src)

        if command == _SMB1_TRANS2:
            if request and len(data) >= 67:
                (subcommand,) = struct.unpack("<H", data[65:67])
                if subcommand == _TRANS2_SESSION_SETUP:
                    self._probes[key].add(pkt)
                    self._probe_counts[key] += 1
                    self._probe_mids[key].add(mid)
            elif not request and key in self._probes:
                self._probe_replies[key] += 1
                if mid == _DOUBLEPULSAR_PRESENT_MID:
                    self._implant_replies[key] += 1
        elif command == _SMB1_SESSION_SETUP and not request and status == 0:
            self._v1_sessions[key].add(pkt)
            self._v1_session_counts[key] += 1

    def findings(self) -> list[Finding]:
        out = []
        for (client, server), w in self._probes.items():
            implant = self._implant_replies[(client, server)]
            replies = self._probe_replies[(client, server)]
            ping = _DOUBLEPULSAR_PING_MID in self._probe_mids[(client, server)]
            if implant:
                verdict = (f"{server} answered with Multiplex ID {_DOUBLEPULSAR_PRESENT_MID} - "
                           "the DoublePulsar implant is present.")
            elif replies:
                verdict = (f"{server} answered {replies} time(s) without the implant's "
                           "Multiplex ID - no DoublePulsar implant was present when probed.")
            else:
                verdict = f"No reply from {server} was captured."
            out.append(Finding(
                self.rule, "threat", "high",
                f"MS17-010 / DoublePulsar probe against {server}",
                f"{client} sent {self._probe_counts[(client, server)]} SMBv1 Trans2 SESSION_SETUP request(s) to {server}"
                + (" using DoublePulsar's ping Multiplex ID (65)" if ping else "")
                + f". {verdict}",
                client, server, w.first, w.last, w.frames,
                {"requests": self._probe_counts[(client, server)], "replies": replies,
                 "implant_present": bool(implant),
                 "multiplex_ids": sorted(self._probe_mids[(client, server)])},
            ))
        for (client, server), w in self._v1_sessions.items():
            out.append(Finding(
                "smbv1", "threat", "low",
                f"SMBv1 session established with {server}",
                f"{server} accepted an SMBv1 session setup from {client}. SMBv1 is deprecated "
                "and is the protocol MS17-010 exploits; a modern client should negotiate SMB2/3.",
                client, server, w.first, w.last, w.frames,
                {"sessions": self._v1_session_counts[(client, server)]},
            ))
        return out


# --------------------------------------------------------------------------- DNS


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def split_domain(name: str) -> tuple[str, str]:
    """Split a name into (subdomain, registered domain) using the last two labels.

    A public-suffix list would be more accurate (``co.uk``), but two labels is
    enough to group tunnelled queries under the attacker's domain.
    """
    labels = name.rstrip(".").split(".")
    if len(labels) <= 2:
        return "", ".".join(labels)
    return ".".join(labels[:-2]), ".".join(labels[-2:])


class DnsTunnelDetector(Detector):
    """Data encoded in DNS query names: many unique, long, high-entropy subdomains."""

    rule = "dns-tunnel"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._subdomains: dict[str, set[str]] = defaultdict(set)
        self._suspicious: dict[str, int] = Counter()
        self._clients: dict[str, set[str]] = defaultdict(set)
        self._windows: dict[str, _Window] = defaultdict(_Window)

    def observe(self, pkt: Packet) -> None:
        if pkt.dns is None or pkt.dns.is_response:
            return
        for name, _ in pkt.dns.questions:
            sub, domain = split_domain(name.lower())
            if not sub:
                continue
            self._subdomains[domain].add(sub)
            self._clients[domain].add(pkt.src)
            self._windows[domain].add(pkt)
            longest = max(len(label) for label in sub.split("."))
            if longest >= self.config.dns_long_label or (
                len(sub) >= 20 and shannon_entropy(sub.replace(".", "")) >= self.config.dns_min_entropy
            ):
                self._suspicious[domain] += 1

    def findings(self) -> list[Finding]:
        out = []
        for domain, count in self._suspicious.items():
            unique = len(self._subdomains[domain])
            if unique < self.config.dns_min_unique_subdomains:
                continue
            w = self._windows[domain]
            subs = sorted(self._subdomains[domain], key=len, reverse=True)
            out.append(Finding(
                self.rule, "threat", "high" if count >= 100 else "medium",
                f"Possible DNS tunnelling via {domain}",
                f"{unique} unique subdomains of {domain} queried, {count} of them long or "
                f"high-entropy, from {len(self._clients[domain])} client(s).",
                ", ".join(sorted(self._clients[domain])), domain, w.first, w.last, w.frames,
                {"unique_subdomains": unique, "suspicious_queries": count,
                 "longest_examples": subs[:3]},
            ))
        return out


# --------------------------------------------------------------------------- ARP


class ArpSpoofDetector(Detector):
    """ARP cache poisoning: one IPv4 address announced by more than one MAC."""

    rule = "arp-spoof"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._macs: dict[str, Counter] = defaultdict(Counter)
        self._windows: dict[str, _Window] = defaultdict(_Window)

    def observe(self, pkt: Packet) -> None:
        if pkt.network != "arp" or not pkt.arp_sender_ip or pkt.arp_sender_ip == "0.0.0.0":
            return
        self._macs[pkt.arp_sender_ip][pkt.arp_sender_mac] += 1
        self._windows[pkt.arp_sender_ip].add(pkt, keep=10)

    def findings(self) -> list[Finding]:
        out = []
        for ip, macs in self._macs.items():
            if len(macs) < 2:
                continue
            w = self._windows[ip]
            out.append(Finding(
                self.rule, "threat", "high",
                f"Conflicting ARP announcements for {ip}",
                f"{ip} was claimed by {len(macs)} different MAC addresses: "
                + ", ".join(f"{mac} ({n}x)" for mac, n in macs.most_common()) + ".",
                ip, None, w.first, w.last, w.frames,
                {"macs": dict(macs)},
            ))
        return out


# -------------------------------------------------------------------- credentials


def mask(secret: str) -> str:
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


class CleartextCredentialDetector(Detector):
    """Usernames and passwords sent without encryption (FTP, POP3, IMAP, HTTP Basic).

    Secrets are masked before they leave this class, so reports are safe to share.
    """

    rule = "cleartext-credentials"

    _LINE_PROTOCOLS = {21: "FTP", 110: "POP3", 143: "IMAP", 23: "Telnet"}

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._hits: dict[tuple[str, str, str], list] = {}

    def observe(self, pkt: Packet) -> None:
        if not pkt.payload or pkt.tcp_flags is None:
            return
        text = pkt.payload[:2048].decode("latin-1")
        protocol = self._LINE_PROTOCOLS.get(pkt.dport)
        if protocol in ("FTP", "POP3"):
            for line in text.splitlines():
                verb, _, arg = line.partition(" ")
                if verb.upper() in ("USER", "PASS") and arg:
                    self._record(pkt, protocol, verb.upper(), arg.strip())
        elif protocol == "IMAP":
            parts = text.split()
            if len(parts) >= 4 and parts[1].upper() == "LOGIN":
                self._record(pkt, protocol, "USER", parts[2].strip('"'))
                self._record(pkt, protocol, "PASS", parts[3].strip('"'))
        elif text.startswith(("GET ", "POST ", "PUT ", "HEAD ", "DELETE ")):
            for line in text.split("\r\n"):
                name, _, value = line.partition(":")
                if name.lower() == "authorization" and value.strip().lower().startswith("basic "):
                    self._record_basic(pkt, value.strip()[6:])

    def _record_basic(self, pkt: Packet, token: str) -> None:
        import base64
        import binascii
        try:
            decoded = base64.b64decode(token, validate=True).decode("latin-1")
        except (binascii.Error, ValueError):
            return
        user, _, password = decoded.partition(":")
        self._record(pkt, "HTTP Basic", "USER", user)
        self._record(pkt, "HTTP Basic", "PASS", password)

    def _record(self, pkt: Packet, protocol: str, kind: str, value: str) -> None:
        key = (pkt.src, f"{pkt.dst}:{pkt.dport}", protocol)
        entry = self._hits.setdefault(key, [_Window(), {}])
        entry[0].add(pkt)
        entry[1][kind] = value if kind == "USER" else mask(value)

    def findings(self) -> list[Finding]:
        out = []
        for (src, dst, protocol), (window, creds) in self._hits.items():
            has_password = "PASS" in creds
            out.append(Finding(
                self.rule, "threat", "high" if has_password else "low",
                f"{protocol} credentials sent in cleartext",
                f"{src} sent {'a username and password' if has_password else 'a username'} "
                f"to {dst} over unencrypted {protocol}.",
                src, dst, window.first, window.last, window.frames,
                {"protocol": protocol, "username": creds.get("USER"),
                 "password_masked": creds.get("PASS")},
            ))
        return out


# ------------------------------------------------------------------- sensor health


class CaptureHealthDetector(Detector):
    """Properties of the capture that make other tools under-report.

    * Transmit checksum offload: when capturing on a host, outbound packets are
      recorded before the NIC fills in the TCP/UDP checksum.  IDS engines that
      validate checksums drop those packets before detection runs.
    * Segmentation offload: frames larger than the MTU, built by the kernel and
      split by the NIC.  Tools with a 1518-byte snaplen truncate them.
    * Truncation: captured length shorter than the wire length (small snaplen).
    """

    rule = "capture-health"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._checked: Counter = Counter()
        self._bad: Counter = Counter()
        self._bad_window: dict[str, _Window] = defaultdict(_Window)
        self._oversized = _Window()
        self._oversized_count = 0
        self._oversized_max = 0
        self._oversized_by_src: Counter = Counter()
        self._truncated = _Window()
        self._truncated_count = 0

    def observe(self, pkt: Packet) -> None:
        if pkt.l4_checksum_ok is not None:
            self._checked[pkt.src] += 1
            if not pkt.l4_checksum_ok:
                self._bad[pkt.src] += 1
                self._bad_window[pkt.src].add(pkt)
        frame_limit = self.config.mtu_frame + (4 if pkt.vlan is not None else 0)
        if pkt.wire_len > frame_limit:
            self._oversized_count += 1
            self._oversized_max = max(self._oversized_max, pkt.wire_len)
            self._oversized_by_src[pkt.src] += 1
            self._oversized.add(pkt)
        if pkt.truncated:
            self._truncated_count += 1
            self._truncated.add(pkt)

    def findings(self) -> list[Finding]:
        out = []
        for src, bad in self._bad.items():
            ratio = bad / self._checked[src]
            if ratio < self.config.offload_min_ratio and bad < self.config.offload_min_count:
                continue
            w = self._bad_window[src]
            out.append(Finding(
                self.rule, "sensor", "medium",
                f"Invalid checksums on packets from {src} (likely checksum offload)",
                f"{bad:,} of {self._checked[src]:,} TCP/UDP/ICMP packets from {src} ({ratio:.0%}) carry "
                "an invalid checksum. Bad checksums concentrated on one host are what a capture taken on "
                "that host looks like when the NIC computes checksums after capture. IDS engines that "
                "verify checksums (Snort, Suricata by default) will discard these packets unseen.",
                src, None, w.first, w.last, w.frames,
                {"bad": bad, "checked": self._checked[src], "ratio": round(ratio, 3),
                 "remedy": "disable checksum validation (Snort: checksum_eval = 'none'; "
                           "Suricata: -k none) or capture with offload off / out of band"},
            ))
        if self._oversized_count:
            w = self._oversized
            out.append(Finding(
                self.rule, "sensor", "medium",
                "Frames larger than the Ethernet MTU (segmentation offload)",
                f"{self._oversized_count:,} frames exceed {self.config.mtu_frame} bytes (largest "
                f"{self._oversized_max:,} B), mostly from "
                + ", ".join(f"{s} ({n})" for s, n in self._oversized_by_src.most_common(3))
                + ". Tools reading with a default 1518-byte snaplen will truncate them and may "
                "reject them as malformed.",
                None, None, w.first, w.last, w.frames,
                {"count": self._oversized_count, "largest": self._oversized_max,
                 "remedy": "raise the reader's snaplen (Snort: -s 65535) or disable TSO/GSO/GRO"},
            ))
        if self._truncated_count:
            w = self._truncated
            out.append(Finding(
                self.rule, "sensor", "low",
                "Packets truncated by the capture snaplen",
                f"{self._truncated_count:,} packets were captured shorter than their wire length; "
                "payload-based detections cannot see the missing bytes.",
                None, None, w.first, w.last, w.frames,
                {"count": self._truncated_count},
            ))
        return out


def default_detectors(config: Config) -> list[Detector]:
    return [
        PortScanDetector(config),
        HostSweepDetector(config),
        C2Detector(config),
        SmbExploitDetector(config),
        DnsTunnelDetector(config),
        ArpSpoofDetector(config),
        CleartextCredentialDetector(config),
        CaptureHealthDetector(config),
    ]
