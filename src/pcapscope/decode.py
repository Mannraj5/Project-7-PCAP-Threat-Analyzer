"""Protocol decoders: link layer -> IPv4/IPv6/ARP -> TCP/UDP/ICMP -> DNS.

Every decoder works on a ``memoryview``-free ``bytes`` slice and fills in a
flat :class:`Packet`.  Decoding never raises on malformed input; a packet that
cannot be fully decoded keeps whatever layers did parse and records the
reason in :attr:`Packet.error`.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .reader import Frame

# Link types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
# IPv6 extension headers that use the generic (next header, length) layout.
_IPV6_EXT_HEADERS = {0, 43, 60, 135, 139, 140}
_IPV6_FRAGMENT = 44

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

DNS_PORTS = {53, 5353, 5355}


@dataclass(slots=True)
class DnsMessage:
    is_response: bool
    rcode: int
    questions: list[tuple[str, int]]   # (name, qtype)


@dataclass(slots=True)
class Packet:
    """A decoded packet.  Fields for layers that are absent stay ``None``."""

    index: int
    timestamp: float
    wire_len: int
    cap_len: int

    # Link layer
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: int | None = None
    vlan: int | None = None

    # Network layer
    network: str | None = None          # "ipv4", "ipv6", "arp" or None
    src: str | None = None
    dst: str | None = None
    ttl: int | None = None
    protocol: int | None = None         # IP protocol number
    fragmented: bool = False
    ip_checksum_ok: bool | None = None

    # ARP
    arp_op: int | None = None           # 1 = request, 2 = reply
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_ip: str | None = None

    # Transport layer
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None
    l4_checksum_ok: bool | None = None  # None when it cannot be verified
    icmp_type: int | None = None
    icmp_code: int | None = None
    payload: bytes = b""

    # Application layer
    dns: DnsMessage | None = None

    error: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def transport(self) -> str | None:
        return {IPPROTO_TCP: "tcp", IPPROTO_UDP: "udp", IPPROTO_ICMP: "icmp",
                IPPROTO_ICMPV6: "icmpv6"}.get(self.protocol) if self.protocol is not None else None

    @property
    def truncated(self) -> bool:
        return self.cap_len < self.wire_len

    def has_flags(self, flags: int, without: int = 0) -> bool:
        if self.tcp_flags is None:
            return False
        return (self.tcp_flags & flags) == flags and not (self.tcp_flags & without)


def decode(frame: Frame) -> Packet:
    pkt = Packet(frame.index, frame.timestamp, frame.orig_len, len(frame.data))
    data = frame.data
    try:
        if frame.linktype == LINKTYPE_ETHERNET:
            _decode_ethernet(pkt, data)
        elif frame.linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
            _decode_ip(pkt, data)
        elif frame.linktype == LINKTYPE_LINUX_SLL:
            (pkt.ethertype,) = struct.unpack("!H", data[14:16])
            _decode_ethertype(pkt, pkt.ethertype, data[16:])
        elif frame.linktype == LINKTYPE_LINUX_SLL2:
            (pkt.ethertype,) = struct.unpack("!H", data[0:2])
            _decode_ethertype(pkt, pkt.ethertype, data[20:])
        elif frame.linktype == LINKTYPE_NULL:
            _decode_ip(pkt, data[4:])  # 4-byte address family in host byte order
        else:
            pkt.error = f"unsupported link type {frame.linktype}"
    except (struct.error, IndexError, ValueError, OSError) as exc:
        pkt.error = f"malformed: {exc}"
    return pkt


def mac_str(raw: bytes) -> str:
    return raw.hex(":")


def checksum_ok(data: bytes) -> bool:
    """True if the one's-complement sum over ``data`` is 0xFFFF.

    Uses the identity 2**16 == 1 (mod 0xFFFF): reading the buffer as one big
    integer and reducing mod 0xFFFF gives the end-around-carry sum of its
    16-bit words, without a Python-level loop.
    """
    if len(data) % 2:
        data += b"\x00"
    return int.from_bytes(data, "big") % 0xFFFF == 0


def _decode_ethernet(pkt: Packet, data: bytes) -> None:
    pkt.dst_mac = mac_str(data[0:6])
    pkt.src_mac = mac_str(data[6:12])
    (ethertype,) = struct.unpack("!H", data[12:14])
    offset = 14
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        tci, ethertype = struct.unpack("!HH", data[offset:offset + 4])
        if pkt.vlan is None:
            pkt.vlan = tci & 0x0FFF
        offset += 4
    pkt.ethertype = ethertype
    _decode_ethertype(pkt, ethertype, data[offset:])


def _decode_ethertype(pkt: Packet, ethertype: int, data: bytes) -> None:
    if ethertype == ETHERTYPE_IPV4 or ethertype == ETHERTYPE_IPV6:
        _decode_ip(pkt, data)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(pkt, data)


def _decode_ip(pkt: Packet, data: bytes) -> None:
    version = data[0] >> 4
    if version == 4:
        _decode_ipv4(pkt, data)
    elif version == 6:
        _decode_ipv6(pkt, data)
    else:
        pkt.error = f"unknown IP version {version}"


def _decode_arp(pkt: Packet, data: bytes) -> None:
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
    pkt.network = "arp"
    pkt.arp_op = op
    if htype != 1 or ptype != ETHERTYPE_IPV4 or hlen != 6 or plen != 4:
        return
    pkt.arp_sender_mac = mac_str(data[8:14])
    pkt.arp_sender_ip = socket.inet_ntoa(data[14:18])
    pkt.arp_target_ip = socket.inet_ntoa(data[24:28])
    pkt.src, pkt.dst = pkt.arp_sender_ip, pkt.arp_target_ip


def _decode_ipv4(pkt: Packet, data: bytes) -> None:
    ihl = (data[0] & 0x0F) * 4
    total_len, frag, ttl, proto = struct.unpack("!H2xHBB", data[2:10])
    header = data[:ihl]
    pkt.network = "ipv4"
    pkt.ttl = ttl
    pkt.protocol = proto
    pkt.src = socket.inet_ntoa(data[12:16])
    pkt.dst = socket.inet_ntoa(data[16:20])

    more_fragments = bool(frag & 0x2000)
    frag_offset = frag & 0x1FFF
    pkt.fragmented = more_fragments or frag_offset > 0
    if len(header) == ihl:
        pkt.ip_checksum_ok = checksum_ok(header)

    # total_len of 0 is legitimate with TSO-built frames captured on the sender;
    # fall back to the captured length in that case.
    end = total_len if total_len >= ihl else len(data)
    segment = data[ihl:end]
    if frag_offset:
        return  # not the first fragment: no transport header here
    complete = len(data) >= end and not pkt.fragmented
    pseudo = data[12:20] + struct.pack("!xBH", proto, len(segment))
    _decode_transport(pkt, proto, segment, pseudo if complete else None)


def _decode_ipv6(pkt: Packet, data: bytes) -> None:
    payload_len, next_header, hop_limit = struct.unpack("!HBB", data[4:8])
    pkt.network = "ipv6"
    pkt.ttl = hop_limit
    pkt.src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    pkt.dst = socket.inet_ntop(socket.AF_INET6, data[24:40])

    offset = 40
    end = 40 + payload_len if payload_len else len(data)
    while next_header in _IPV6_EXT_HEADERS or next_header == _IPV6_FRAGMENT:
        if next_header == _IPV6_FRAGMENT:
            (frag,) = struct.unpack("!H", data[offset + 2:offset + 4])
            pkt.fragmented = True
            next_header = data[offset]
            offset += 8
            if frag & 0xFFF8:
                pkt.protocol = next_header
                return
            continue
        ext_len = (data[offset + 1] + 1) * 8
        next_header = data[offset]
        offset += ext_len

    pkt.protocol = next_header
    segment = data[offset:end]
    complete = len(data) >= end and not pkt.fragmented
    pseudo = data[8:40] + struct.pack("!I3xB", len(segment), next_header)
    _decode_transport(pkt, next_header, segment, pseudo if complete else None)


def _decode_transport(pkt: Packet, proto: int, segment: bytes, pseudo: bytes | None) -> None:
    if proto == IPPROTO_TCP:
        sport, dport, offset_flags = struct.unpack("!HH8xH", segment[:14])
        header_len = (offset_flags >> 12) * 4
        pkt.sport, pkt.dport = sport, dport
        pkt.tcp_flags = offset_flags & 0x01FF
        pkt.payload = segment[header_len:]
        if pseudo is not None:
            pkt.l4_checksum_ok = checksum_ok(pseudo + segment)
    elif proto == IPPROTO_UDP:
        sport, dport, _, udp_sum = struct.unpack("!HHHH", segment[:8])
        pkt.sport, pkt.dport = sport, dport
        pkt.payload = segment[8:]
        # A zero UDP checksum over IPv4 means "not computed".
        if pseudo is not None and not (udp_sum == 0 and pkt.network == "ipv4"):
            pkt.l4_checksum_ok = checksum_ok(pseudo + segment)
        if sport in DNS_PORTS or dport in DNS_PORTS:
            pkt.dns = _decode_dns(pkt.payload)
    elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        pkt.icmp_type, pkt.icmp_code = segment[0], segment[1]
        pkt.payload = segment[4:]
        if pseudo is not None:
            pkt.l4_checksum_ok = checksum_ok(segment if proto == IPPROTO_ICMP else pseudo + segment)


def _decode_dns(data: bytes) -> DnsMessage | None:
    if len(data) < 12:
        return None
    _, flags, qdcount = struct.unpack("!HHH", data[:6])
    questions = []
    offset = 12
    for _ in range(min(qdcount, 16)):
        name, offset = _read_dns_name(data, offset)
        if name is None or offset + 4 > len(data):
            break
        (qtype,) = struct.unpack("!H", data[offset:offset + 2])
        offset += 4
        questions.append((name, qtype))
    return DnsMessage(bool(flags & 0x8000), flags & 0x000F, questions)


def _read_dns_name(data: bytes, offset: int) -> tuple[str | None, int]:
    """Read a (possibly compressed) DNS name; returns (name, offset after it)."""
    labels: list[str] = []
    end = None
    jumps = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data) or jumps > 16:
                return None, offset
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            continue
        label = data[offset + 1:offset + 1 + length]
        labels.append(label.decode("ascii", errors="replace"))
        offset += 1 + length
    else:
        return None, offset
    return ".".join(labels), end if end is not None else offset
