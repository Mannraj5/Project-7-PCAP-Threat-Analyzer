"""Build valid frames and capture files byte by byte.

Used by the test suite and by ``scripts/make_demo_capture.py`` to produce
traffic the real lab captures do not contain (DNS tunnelling, ARP spoofing,
cleartext credentials, beaconing).  Checksums are computed correctly unless
``bad_checksum`` is set, which mimics a capture taken with checksum offload.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from .decode import TCP_ACK, TCP_PSH, TCP_SYN

DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(payload: bytes, ethertype: int = 0x0800, src_mac: str = DEFAULT_SRC_MAC,
             dst_mac: str = DEFAULT_DST_MAC, vlan: int | None = None) -> bytes:
    header = _mac(dst_mac) + _mac(src_mac)
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan)
    return header + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 1,
         flags_frag: int = 0x4000) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags_frag,
                         ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    return (struct.pack("!IHBB", 6 << 28, len(payload), next_header, hop_limit)
            + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
            + payload)


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if ":" in src:
        return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!I3xB", length, proto))
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!xBH", proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, flags: int = TCP_ACK | TCP_PSH,
        payload: bytes = b"", seq: int = 1, ack: int = 1, bad_checksum: bool = False) -> bytes:
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 64240, 0, 0)
    segment = header + payload
    csum = _checksum(_pseudo(src, dst, 6, len(segment)) + segment)
    if bad_checksum:
        csum ^= 0x5A5A
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"",
        bad_checksum: bool = False) -> bytes:
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = _checksum(_pseudo(src, dst, 17, len(segment)) + segment) or 0xFFFF
    if bad_checksum:
        csum ^= 0x5A5A
    return segment[:6] + struct.pack("!H", csum) + segment[8:]


def icmp_echo(ident: int = 1, seq: int = 1, payload: bytes = b"ping") -> bytes:
    msg = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    return msg[:2] + struct.pack("!H", _checksum(msg)) + msg[4:]


def arp(op: int, sender_mac: str, sender_ip: str, target_ip: str,
        target_mac: str = "00:00:00:00:00:00") -> bytes:
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + _mac(sender_mac)
            + socket.inet_aton(sender_ip) + _mac(target_mac) + socket.inet_aton(target_ip))


def dns_query(name: str, qtype: int = 1, ident: int = 0x1234) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


# ------------------------------------------------------------------ convenience


def tcp_frame(src: str, dst: str, sport: int, dport: int, flags: int = TCP_ACK | TCP_PSH,
              payload: bytes = b"", bad_checksum: bool = False, **eth) -> bytes:
    return ethernet(ipv4(src, dst, 6, tcp(src, dst, sport, dport, flags, payload,
                                          bad_checksum=bad_checksum)), **eth)


def syn_frame(src: str, dst: str, sport: int, dport: int, **eth) -> bytes:
    return tcp_frame(src, dst, sport, dport, TCP_SYN, **eth)


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes = b"",
              bad_checksum: bool = False, **eth) -> bytes:
    return ethernet(ipv4(src, dst, 17, udp(src, dst, sport, dport, payload, bad_checksum)), **eth)


def dns_frame(src: str, dst: str, name: str, sport: int = 53000) -> bytes:
    return udp_frame(src, dst, sport, 53, dns_query(name))


def arp_frame(op: int, sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    dst = "ff:ff:ff:ff:ff:ff" if op == 1 else DEFAULT_DST_MAC
    return ethernet(arp(op, sender_mac, sender_ip, target_ip), 0x0806, sender_mac, dst)


# ------------------------------------------------------------------ file writers


def write_pcap(path: str | Path, packets: list[tuple[float, bytes]], linktype: int = 1,
               nanosecond: bool = False, big_endian: bool = False, snaplen: int = 65535) -> None:
    endian = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    ticks = 1_000_000_000 if nanosecond else 1_000_000
    with open(path, "wb") as out:
        out.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
        for ts, data in packets:
            seconds = int(ts)
            fraction = round((ts - seconds) * ticks)
            captured = data[:snaplen]
            out.write(struct.pack(endian + "IIII", seconds, fraction, len(captured), len(data)))
            out.write(captured)


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def _block(block_type: int, body: bytes, endian: str) -> bytes:
    body = _pad4(body)
    length = 12 + len(body)
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def write_pcapng(path: str | Path, packets: list[tuple[float, bytes]], linktype: int = 1,
                 tsresol: int | None = None, big_endian: bool = False) -> None:
    """Write a single-section, single-interface pcapng file of Enhanced Packet Blocks."""
    endian = ">" if big_endian else "<"
    ticks = 1_000_000
    options = b""
    if tsresol is not None:
        options = struct.pack(endian + "HH", 9, 1) + _pad4(bytes([tsresol])) + struct.pack(endian + "HH", 0, 0)
        ticks = 2 ** (tsresol & 0x7F) if tsresol & 0x80 else 10 ** tsresol

    with open(path, "wb") as out:
        out.write(_block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian))
        out.write(_block(0x00000001, struct.pack(endian + "HHI", linktype, 0, 0) + options, endian))
        for ts, data in packets:
            stamp = round(ts * ticks)
            body = struct.pack(endian + "IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF,
                               len(data), len(data)) + data
            out.write(_block(0x00000006, body, endian))
