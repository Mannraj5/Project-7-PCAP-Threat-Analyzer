"""Capture file readers for classic pcap and pcapng.

Both formats are parsed directly from bytes with ``struct``; no libpcap,
scapy or dpkt.  The reader yields one :class:`Frame` per captured packet and
leaves all protocol decoding to :mod:`pcapscope.decode`.

References:
    classic pcap  - https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-04.html
    pcapng        - https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

# Classic pcap magic numbers, as read with little-endian byte order.
_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),      # little-endian, microsecond
    0xD4C3B2A1: (">", 1_000_000),      # big-endian, microsecond
    0xA1B23C4D: ("<", 1_000_000_000),  # little-endian, nanosecond
    0x4D3CB2A1: (">", 1_000_000_000),  # big-endian, nanosecond
}

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_IDB_OPT_TSRESOL = 9


class CaptureError(ValueError):
    """Raised when a file is not a readable pcap/pcapng capture."""


@dataclass(frozen=True, slots=True)
class Frame:
    """One captured packet, before any protocol decoding."""

    index: int          # 1-based, matches Wireshark's frame number
    timestamp: float    # seconds since the Unix epoch
    linktype: int       # LINKTYPE_* value for the interface it was seen on
    data: bytes         # captured bytes (may be shorter than orig_len)
    orig_len: int       # length of the packet on the wire


@dataclass(slots=True)
class _Interface:
    linktype: int
    snaplen: int
    ticks_per_second: int = 1_000_000


def read_capture(path: str | Path) -> Iterator[Frame]:
    """Yield every frame in ``path``, auto-detecting pcap or pcapng."""
    with open(path, "rb") as stream:
        magic = stream.read(4)
        if len(magic) < 4:
            raise CaptureError(f"{path}: file is too short to be a capture")
        stream.seek(0)
        (value,) = struct.unpack("<I", magic)
        if value in _PCAP_MAGICS:
            yield from _read_pcap(stream)
        elif value == _PCAPNG_SHB:
            yield from _read_pcapng(stream)
        else:
            raise CaptureError(f"{path}: unrecognised magic number 0x{value:08x}")


def _read_exact(stream: BinaryIO, size: int, what: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise CaptureError(f"truncated capture while reading {what}")
    return data


def _read_pcap(stream: BinaryIO) -> Iterator[Frame]:
    header = _read_exact(stream, 24, "pcap global header")
    (magic,) = struct.unpack("<I", header[:4])
    endian, ticks = _PCAP_MAGICS[magic]
    # magic, version major/minor, thiszone, sigfigs, snaplen, link type
    *_, linktype = struct.unpack(endian + "IHHiIII", header)
    # The upper 4 bits of the link-type field hold FCS info; the type is the low 28.
    linktype &= 0x0FFFFFFF

    record = struct.Struct(endian + "IIII")
    index = 0
    while True:
        raw = stream.read(record.size)
        if len(raw) < record.size:
            # End of file, or a capture cut off mid-header (e.g. tcpdump killed).
            return
        seconds, fraction, incl_len, orig_len = record.unpack(raw)
        data = stream.read(incl_len)
        if len(data) < incl_len:
            return
        index += 1
        yield Frame(index, seconds + fraction / ticks, linktype, data, orig_len)


def _read_pcapng(stream: BinaryIO) -> Iterator[Frame]:
    endian = "<"
    interfaces: list[_Interface] = []
    index = 0

    while True:
        head = stream.read(8)
        if len(head) < 8:
            return

        (block_type,) = struct.unpack("<I", head[:4])
        if block_type == _PCAPNG_SHB:
            # The byte-order magic decides how this section (and its length field) is read.
            bom = _read_exact(stream, 4, "section header byte-order magic")
            if struct.unpack("<I", bom)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
                endian = ">"
            else:
                raise CaptureError("pcapng section header has an invalid byte-order magic")
            (total_len,) = struct.unpack(endian + "I", head[4:])
            _read_exact(stream, total_len - 12, "section header block")
            interfaces = []  # interface IDs are scoped to their section
            continue

        block_type, total_len = struct.unpack(endian + "II", head)
        if total_len < 12 or total_len % 4:
            raise CaptureError(f"pcapng block has invalid length {total_len}")
        body = _read_exact(stream, total_len - 8, "pcapng block")[:-4]  # drop trailing length

        if block_type == _PCAPNG_IDB:
            interfaces.append(_parse_idb(body, endian))
        elif block_type == _PCAPNG_EPB:
            iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            iface = interfaces[iface_id]
            ticks = (ts_high << 32) | ts_low
            index += 1
            yield Frame(index, ticks / iface.ticks_per_second, iface.linktype,
                        body[20:20 + cap_len], orig_len)
        elif block_type == _PCAPNG_SPB:
            (orig_len,) = struct.unpack(endian + "I", body[:4])
            iface = interfaces[0]
            cap_len = min(orig_len, iface.snaplen or orig_len, len(body) - 4)
            index += 1
            # Simple packet blocks carry no timestamp.
            yield Frame(index, 0.0, iface.linktype, body[4:4 + cap_len], orig_len)
        # Name resolution, statistics, custom and decryption-secret blocks are skipped.


def _parse_idb(body: bytes, endian: str) -> _Interface:
    linktype, _, snaplen = struct.unpack(endian + "HHI", body[:8])
    iface = _Interface(linktype, snaplen)

    offset = 8
    while offset + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[offset:offset + 4])
        if code == 0:  # opt_endofopt
            break
        value = body[offset + 4:offset + 4 + length]
        if code == _IDB_OPT_TSRESOL and value:
            resolution = value[0]
            # High bit set: negative power of 2; otherwise negative power of 10.
            if resolution & 0x80:
                iface.ticks_per_second = 2 ** (resolution & 0x7F)
            else:
                iface.ticks_per_second = 10 ** resolution
        offset += 4 + length + (-length % 4)
    return iface
