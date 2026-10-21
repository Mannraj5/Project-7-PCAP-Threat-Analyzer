import base64
import struct

import pytest

from pcapscope import analyze, craft
from pcapscope.decode import TCP_ACK, TCP_SYN
from pcapscope.detect import mask, shannon_entropy, split_domain

ATTACKER, VICTIM, CLIENT = "10.0.0.66", "10.0.0.20", "10.0.0.5"


def run(tmp_path, frames, **config):
    path = tmp_path / "t.pcap"
    craft.write_pcap(path, frames)
    from pcapscope.detect import Config
    return analyze(path, Config(**config))


def rules(result):
    return {f.rule for f in result.findings}


def by_rule(result, rule):
    return [f for f in result.findings if f.rule == rule]


def test_port_scan_counts_open_ports(tmp_path):
    frames = []
    t = 1000.0
    for port in range(1, 501):
        frames.append((t, craft.syn_frame(ATTACKER, VICTIM, 50000, port)))
        t += 0.001
    # 8080 answers SYN-ACK but was never probed by this scanner, so it must not count.
    for port in (22, 80, 445, 8080):
        frames.append((t, craft.tcp_frame(VICTIM, ATTACKER, port, 50000, TCP_SYN | TCP_ACK)))
    result = run(tmp_path, frames)
    (scan,) = by_rule(result, "port-scan")
    assert scan.src == ATTACKER and scan.dst == VICTIM
    assert scan.evidence["ports_probed"] == 500
    assert scan.evidence["open_ports"] == [22, 80, 445]
    assert scan.severity == "medium"


def test_normal_browsing_is_not_a_scan_or_sweep(tmp_path):
    # 60 HTTPS connections to 60 different public servers in one minute.
    frames = [(1000.0 + i, craft.syn_frame(CLIENT, f"93.184.{i}.10", 50000 + i, 443)) for i in range(60)]
    assert rules(run(tmp_path, frames)) == set()


def test_syn_sweep_of_local_subnet(tmp_path):
    frames = [(1000.0 + i / 100, craft.syn_frame(ATTACKER, f"10.0.0.{i}", 50000, 445)) for i in range(1, 41)]
    (sweep,) = by_rule(run(tmp_path, frames), "host-sweep")
    assert sweep.evidence["method"] == "TCP SYN" and sweep.evidence["hosts_probed"] == 40


def test_arp_sweep(tmp_path):
    frames = [(1000.0 + i / 10, craft.arp_frame(1, "02:00:00:00:00:66", ATTACKER, f"10.0.0.{i}"))
              for i in range(1, 60)]
    (sweep,) = by_rule(run(tmp_path, frames), "host-sweep")
    assert sweep.evidence["method"] == "ARP" and sweep.evidence["hosts_probed"] == 59
    assert sweep.evidence["sample_targets"][:3] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_session_on_metasploit_port(tmp_path):
    frames = [(1000.0, craft.syn_frame(VICTIM, ATTACKER, 49200, 4444))]
    frames += [(1001.0 + i, craft.tcp_frame(ATTACKER, VICTIM, 4444, 49200, payload=b"\x00" * 1400))
               for i in range(10)]
    (c2,) = by_rule(run(tmp_path, frames), "c2")
    assert (c2.src, c2.dst) == (VICTIM, ATTACKER)
    assert c2.evidence["bytes_server_to_client"] == 14000
    assert c2.severity == "high"


def test_session_after_port_scan_is_attributed_correctly(tmp_path):
    # Regression: the scanner probed every port on the victim, including the
    # ephemeral port the victim later uses for its reverse shell.  Shell traffic
    # from the attacker must still count as server -> client on the 4444 session.
    frames = [(1000.0 + p / 10000, craft.syn_frame(ATTACKER, VICTIM, 60000, p)) for p in range(1, 65536, 7)]
    ephemeral = 49158  # == 1 + 7 * 7022, so it was scanned above
    frames.append((2000.0, craft.syn_frame(VICTIM, ATTACKER, ephemeral, 4444)))
    frames += [(2001.0 + i, craft.tcp_frame(ATTACKER, VICTIM, 4444, ephemeral, payload=b"\x90" * 1000))
               for i in range(20)]
    (c2,) = by_rule(run(tmp_path, frames), "c2")
    assert c2.evidence["bytes_server_to_client"] == 20_000
    assert c2.evidence["bytes_client_to_server"] == 0


def test_refused_connection_to_suspicious_port_is_ignored(tmp_path):
    frames = [(1000.0, craft.syn_frame(VICTIM, ATTACKER, 49200, 4444)),
              (1000.1, craft.tcp_frame(ATTACKER, VICTIM, 4444, 49200, 0x14))]  # RST/ACK
    assert "c2" not in rules(run(tmp_path, frames))


def test_beaconing_regular_interval(tmp_path):
    frames = [(1000.0 + 60 * i + (i % 2), craft.syn_frame(CLIENT, "203.0.113.9", 50000 + i, 8080))
              for i in range(10)]
    (beacon,) = by_rule(run(tmp_path, frames), "beacon")
    assert beacon.evidence["connections"] == 10
    assert beacon.evidence["mean_interval_s"] == pytest.approx(60, abs=1)


def test_irregular_connections_are_not_beacons(tmp_path):
    times = [0, 3, 50, 52, 300, 301, 900, 1500]
    frames = [(1000.0 + t, craft.syn_frame(CLIENT, "203.0.113.9", 50000 + i, 8080)) for i, t in enumerate(times)]
    assert "beacon" not in rules(run(tmp_path, frames))


def test_dns_tunnel(tmp_path):
    import random
    rng = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    frames = []
    for i in range(40):
        chunk = "".join(rng.choice(alphabet) for _ in range(52))
        frames.append((1000.0 + i, craft.dns_frame(CLIENT, "8.8.8.8", f"{chunk}.{i}.t.evil-c2.net")))
    # Ordinary lookups must not be flagged.
    for i, name in enumerate(["www.google.com", "mail.google.com", "docs.google.com"] * 10):
        frames.append((2000.0 + i, craft.dns_frame(CLIENT, "8.8.8.8", name)))
    result = run(tmp_path, frames)
    (tunnel,) = by_rule(result, "dns-tunnel")
    assert tunnel.dst == "evil-c2.net"
    assert tunnel.evidence["unique_subdomains"] == 40


def test_arp_spoofing(tmp_path):
    frames = [
        (1000.0, craft.arp_frame(2, "02:aa:aa:aa:aa:01", "10.0.0.1", CLIENT)),   # real gateway
        (1001.0, craft.arp_frame(2, "02:66:66:66:66:66", "10.0.0.1", CLIENT)),   # attacker
        (1002.0, craft.arp_frame(2, "02:66:66:66:66:66", "10.0.0.1", CLIENT)),
    ]
    (spoof,) = by_rule(run(tmp_path, frames), "arp-spoof")
    assert spoof.src == "10.0.0.1"
    assert spoof.evidence["macs"] == {"02:66:66:66:66:66": 2, "02:aa:aa:aa:aa:01": 1}


@pytest.mark.parametrize("port,payloads,protocol", [
    (21, [b"USER alice\r\n", b"PASS hunter22\r\n"], "FTP"),
    (110, [b"USER alice\r\n", b"PASS hunter22\r\n"], "POP3"),
    (143, [b'a1 LOGIN alice "hunter22"\r\n'], "IMAP"),
    (80, [b"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
          + base64.b64encode(b"alice:hunter22") + b"\r\n\r\n"], "HTTP Basic"),
])
def test_cleartext_credentials_are_found_and_masked(tmp_path, port, payloads, protocol):
    frames = [(1000.0 + i, craft.tcp_frame(CLIENT, "10.0.0.25", 50000, port, payload=p))
              for i, p in enumerate(payloads)]
    (cred,) = by_rule(run(tmp_path, frames), "cleartext-credentials")
    assert cred.evidence["protocol"] == protocol
    assert cred.evidence["username"] == "alice"
    assert cred.evidence["password_masked"] == "h******2"
    assert "hunter22" not in str(cred)


def _smb1(command: int, mid: int, body: bytes = b"", status: int = 0) -> bytes:
    # 32-byte SMB1 header: magic, command, status, flags, flags2, PIDHigh, signature,
    # reserved, then TID, PIDLow, UID and MID at offset 30.
    header = b"\xffSMB" + bytes([command]) + struct.pack("<I", status) + b"\x18" + b"\x07\xc8"
    header += b"\x00" * 12 + struct.pack("<HHHH", 0, 0, 0, mid)
    assert len(header) == 32
    message = header + body
    return struct.pack(">I", len(message)) + message


def _trans2_session_setup(mid: int) -> bytes:
    words = b"\x00" * 28 + struct.pack("<H", 0x000E)   # Setup[0] = SESSION_SETUP
    return _smb1(0x32, mid, bytes([15]) + words + b"\x00" * 4)


@pytest.mark.parametrize("reply_mid,implant", [(65, False), (81, True)])
def test_doublepulsar_probe(tmp_path, reply_mid, implant):
    frames = [
        (1000.0, craft.tcp_frame(ATTACKER, VICTIM, 40000, 445, payload=_trans2_session_setup(65))),
        (1000.1, craft.tcp_frame(VICTIM, ATTACKER, 445, 40000,
                                 payload=_smb1(0x32, reply_mid, status=0xC0000002))),
    ]
    (probe,) = by_rule(run(tmp_path, frames), "smb-exploit")
    assert probe.evidence["implant_present"] is implant
    assert probe.evidence["multiplex_ids"] == [65]


def test_smbv1_negotiate_alone_is_not_flagged(tmp_path):
    frames = [(1000.0, craft.tcp_frame(CLIENT, VICTIM, 40000, 445, payload=_smb1(0x72, 1)))]
    assert rules(run(tmp_path, frames)) == set()


def test_checksum_offload_on_one_host(tmp_path):
    frames = []
    for i in range(50):
        frames.append((1000.0 + i, craft.tcp_frame(ATTACKER, VICTIM, 4444, 50000, payload=b"x", bad_checksum=True)))
        frames.append((1000.5 + i, craft.tcp_frame(VICTIM, ATTACKER, 50000, 4444, payload=b"y")))
    result = run(tmp_path, frames)
    sensor = result.sensor_findings
    assert [f.src for f in sensor if "checksum" in f.title] == [ATTACKER]


def test_oversized_frames(tmp_path):
    big = craft.tcp_frame(ATTACKER, VICTIM, 4444, 50000, payload=b"A" * 7000)
    (finding,) = [f for f in run(tmp_path, [(1000.0, big)]).sensor_findings if "MTU" in f.title]
    assert finding.evidence["largest"] == len(big)


def test_helpers():
    assert mask("hunter22") == "h******2" and mask("ab") == "**"
    assert split_domain("a.b.example.com") == ("a.b", "example.com")
    assert split_domain("example.com") == ("", "example.com")
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
