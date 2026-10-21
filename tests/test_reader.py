import struct

import pytest

from pcapscope import CaptureError, read_capture
from pcapscope.craft import syn_frame, write_pcap, write_pcapng

FRAMES = [
    (1_700_000_000.250000, syn_frame("10.0.0.1", "10.0.0.2", 40000, 80)),
    (1_700_000_001.500000, syn_frame("10.0.0.1", "10.0.0.2", 40001, 443)),
    (1_700_000_002.750000, syn_frame("10.0.0.1", "10.0.0.3", 40002, 22)),
]


def _assert_round_trip(frames, path, tolerance=1e-6):
    assert len(frames) == len(FRAMES)
    for i, (frame, (ts, data)) in enumerate(zip(frames, FRAMES), 1):
        assert frame.index == i
        assert frame.data == data
        assert frame.orig_len == len(data)
        assert frame.linktype == 1
        assert frame.timestamp == pytest.approx(ts, abs=tolerance)


@pytest.mark.parametrize("big_endian", [False, True])
@pytest.mark.parametrize("nanosecond", [False, True])
def test_pcap_all_magic_variants(tmp_path, big_endian, nanosecond):
    path = tmp_path / "c.pcap"
    write_pcap(path, FRAMES, nanosecond=nanosecond, big_endian=big_endian)
    _assert_round_trip(list(read_capture(path)), path)


@pytest.mark.parametrize("big_endian", [False, True])
@pytest.mark.parametrize("tsresol", [None, 9, 0x80 | 20])
def test_pcapng_byte_orders_and_resolutions(tmp_path, big_endian, tsresol):
    path = tmp_path / "c.pcapng"
    write_pcapng(path, FRAMES, tsresol=tsresol, big_endian=big_endian)
    _assert_round_trip(list(read_capture(path)), path)


def test_pcap_snaplen_truncation_is_reported(tmp_path):
    path = tmp_path / "short.pcap"
    write_pcap(path, FRAMES, snaplen=40)
    frames = list(read_capture(path))
    assert all(len(f.data) == 40 for f in frames)
    assert [f.orig_len for f in frames] == [len(d) for _, d in FRAMES]


def test_capture_cut_off_mid_record_keeps_complete_frames(tmp_path):
    path = tmp_path / "cut.pcap"
    write_pcap(path, FRAMES)
    path.write_bytes(path.read_bytes()[:-10])
    assert len(list(read_capture(path))) == 2


def test_pcapng_skips_unknown_blocks(tmp_path):
    path = tmp_path / "extra.pcapng"
    write_pcapng(path, FRAMES)
    raw = path.read_bytes()
    # Insert a custom block (type 0x00000BAD) after the interface description block.
    shb_len = struct.unpack("<I", raw[4:8])[0]
    idb_len = struct.unpack("<I", raw[shb_len + 4:shb_len + 8])[0]
    split = shb_len + idb_len
    custom = struct.pack("<II", 0xBAD, 16) + b"junk" + struct.pack("<I", 16)
    path.write_bytes(raw[:split] + custom + raw[split:])
    assert len(list(read_capture(path))) == 3


def test_rejects_non_capture(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("definitely not a pcap")
    with pytest.raises(CaptureError, match="magic"):
        list(read_capture(path))


def test_rejects_empty_file(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(CaptureError, match="too short"):
        list(read_capture(path))
