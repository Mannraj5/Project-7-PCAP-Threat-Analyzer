import pytest

from pcapscope import craft
from pcapscope.decode import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW, TCP_ACK,
                              TCP_SYN, checksum_ok, decode)
from pcapscope.reader import Frame


def _decode(data: bytes, linktype: int = LINKTYPE_ETHERNET, orig_len: int | None = None):
    return decode(Frame(1, 0.0, linktype, data, orig_len or len(data)))


def test_tcp_over_ipv4():
    pkt = _decode(craft.tcp_frame("192.168.1.10", "192.168.1.20", 51000, 80, payload=b"GET / HTTP/1.1\r\n"))
    assert pkt.network == "ipv4" and pkt.transport == "tcp"
    assert (pkt.src, pkt.dst, pkt.sport, pkt.dport) == ("192.168.1.10", "192.168.1.20", 51000, 80)
    assert pkt.payload == b"GET / HTTP/1.1\r\n"
    assert pkt.ip_checksum_ok is True
    assert pkt.l4_checksum_ok is True
    assert pkt.src_mac == craft.DEFAULT_SRC_MAC


def test_bad_tcp_checksum_is_detected():
    pkt = _decode(craft.tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, payload=b"x", bad_checksum=True))
    assert pkt.l4_checksum_ok is False


def test_syn_flags():
    pkt = _decode(craft.syn_frame("10.0.0.1", "10.0.0.2", 1234, 22))
    assert pkt.has_flags(TCP_SYN, without=TCP_ACK)
    assert not pkt.has_flags(TCP_SYN | TCP_ACK)


def test_vlan_tag_is_unwrapped():
    pkt = _decode(craft.syn_frame("10.0.0.1", "10.0.0.2", 1234, 22, vlan=42))
    assert pkt.vlan == 42 and pkt.transport == "tcp" and pkt.dport == 22


def test_udp_dns_query():
    pkt = _decode(craft.dns_frame("10.0.0.5", "8.8.8.8", "www.example.com"))
    assert pkt.transport == "udp" and pkt.l4_checksum_ok is True
    assert pkt.dns is not None and not pkt.dns.is_response
    assert pkt.dns.questions == [("www.example.com", 1)]


def test_dns_compression_pointer_loop_does_not_hang():
    payload = bytes.fromhex("1234 0100 0001 0000 0000 0000") + b"\xc0\x0c"
    pkt = _decode(craft.udp_frame("10.0.0.5", "8.8.8.8", 5000, 53, payload))
    assert pkt.error is None and pkt.dns.questions == []


def test_arp_request():
    pkt = _decode(craft.arp_frame(1, "aa:bb:cc:dd:ee:ff", "10.0.0.1", "10.0.0.9"))
    assert pkt.network == "arp" and pkt.arp_op == 1
    assert (pkt.arp_sender_mac, pkt.arp_sender_ip, pkt.arp_target_ip) == ("aa:bb:cc:dd:ee:ff", "10.0.0.1", "10.0.0.9")


def test_icmp_echo():
    pkt = _decode(craft.ethernet(craft.ipv4("10.0.0.1", "10.0.0.2", 1, craft.icmp_echo())))
    assert pkt.transport == "icmp" and pkt.icmp_type == 8 and pkt.l4_checksum_ok is True


def test_tcp_over_ipv6():
    seg = craft.tcp("2001:db8::1", "2001:db8::2", 40000, 443, payload=b"hello")
    pkt = _decode(craft.ethernet(craft.ipv6("2001:db8::1", "2001:db8::2", 6, seg), ethertype=0x86DD))
    assert pkt.network == "ipv6" and pkt.src == "2001:db8::1" and pkt.dport == 443
    assert pkt.l4_checksum_ok is True


def test_raw_ip_and_linux_sll_link_types():
    ip = craft.ipv4("10.0.0.1", "10.0.0.2", 6, craft.tcp("10.0.0.1", "10.0.0.2", 1, 2))
    assert _decode(ip, LINKTYPE_RAW).dport == 2
    sll = b"\x00\x00\x00\x01\x00\x06" + b"\x02\x00\x00\x00\x00\x01\x00\x00" + b"\x08\x00"
    assert _decode(sll + ip, LINKTYPE_LINUX_SLL).dport == 2


def test_truncated_packet_is_not_checksum_verified():
    full = craft.tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, payload=b"A" * 200)
    pkt = _decode(full[:60], orig_len=len(full))
    assert pkt.truncated and pkt.dport == 80
    assert pkt.l4_checksum_ok is None


def test_non_first_fragment_has_no_transport_header():
    frag = craft.ethernet(craft.ipv4("10.0.0.1", "10.0.0.2", 17, b"\x00" * 16, flags_frag=0x0001))
    pkt = _decode(frag)
    assert pkt.fragmented and pkt.sport is None and pkt.error is None


@pytest.mark.parametrize("data", [b"", b"\x00" * 5, b"\xff" * 13, b"\x00" * 14 + b"\x45"])
def test_garbage_never_raises(data):
    pkt = _decode(data)
    assert pkt.index == 1


def test_unsupported_link_type_is_recorded():
    assert "unsupported" in _decode(b"\x00" * 40, linktype=147).error


def test_checksum_identity_matches_reference_sum():
    # RFC 1071 example words: 0x0001 f203 f4f5 f6f7 -> sum 0xddf2, checksum 0x220d
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert checksum_ok(data + bytes.fromhex("220d"))
    assert not checksum_ok(data + bytes.fromhex("220e"))
