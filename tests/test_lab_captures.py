"""Validation against real captures from the Purple Team Lab (Project 2).

These files are not shipped with this repository.  Point the environment
variable at the lab's ``pcaps`` directory to run the checks:

    PCAPSCOPE_LAB_CAPTURES=../Project-2-Purple-Team-Lab/pcaps pytest

Expected packet counts come from ``capinfos`` as recorded in that project's
capture inventory; expected detections come from its documented attack chains.
"""

import os
from pathlib import Path

import pytest

from pcapscope import analyze, read_capture

LAB = Path(os.environ.get("PCAPSCOPE_LAB_CAPTURES", "__missing__"))
pytestmark = pytest.mark.skipif(not LAB.is_dir(), reason="set PCAPSCOPE_LAB_CAPTURES to run")

ATTACKER, VICTIM = "192.168.56.10", "192.168.56.20"

CAPINFOS_PACKETS = {
    "baseline-clean-full.pcap": 9_092,
    "chainA-recon.pcap": 132_727,
    "chainA-exploitation.pcap": 493,
    "chainB-clean.pcap": 563,
    "chainA-run1.pcap": 134_478,
    "chainB-run1.pcap": 581,
}


@pytest.mark.parametrize("name,expected", CAPINFOS_PACKETS.items())
def test_packet_counts_match_capinfos(name, expected):
    assert sum(1 for _ in read_capture(LAB / name)) == expected


def _threats(name):
    return {(f.rule, f.src, f.dst) for f in analyze(LAB / name).threats}


def test_baseline_has_no_threat_findings():
    assert _threats("baseline-clean-full.pcap") == set()


def test_recon_finds_full_port_scan_and_arp_sweep():
    result = analyze(LAB / "chainA-recon.pcap")
    (scan,) = [f for f in result.threats if f.rule == "port-scan"]
    assert (scan.src, scan.dst) == (ATTACKER, VICTIM)
    assert scan.evidence["ports_probed"] == 65_535
    assert {22, 135, 139, 445} <= set(scan.evidence["open_ports"])
    assert ("host-sweep", ATTACKER, None) in _threats("chainA-recon.pcap")


def test_chain_a_c2_on_4444():
    assert ("c2", VICTIM, ATTACKER) in _threats("chainA-exploitation.pcap")


def test_c2_session_identical_in_original_and_trimmed_capture():
    # chainA-exploitation is a time-window trim of chainA-run1, which also holds
    # the full port scan.  The 4444 session must be measured identically in both.
    def session(name):
        (f,) = [f for f in analyze(LAB / name).threats if f.rule == "c2" and f.evidence["port"] == 4444]
        return {k: f.evidence[k] for k in ("packets", "bytes_client_to_server", "bytes_server_to_client")}

    assert session("chainA-run1.pcap") == session("chainA-exploitation.pcap") == {
        "packets": 303, "bytes_client_to_server": 116_010, "bytes_server_to_client": 1_077_168}


def test_chain_b_doublepulsar_probe_and_c2_on_5555():
    result = analyze(LAB / "chainB-clean.pcap")
    (probe,) = [f for f in result.threats if f.rule == "smb-exploit"]
    assert probe.evidence["implant_present"] is False
    ports = {f.evidence["port"] for f in result.threats if f.rule == "c2"}
    assert ports == {5555}


def test_chain_b_original_still_contains_residual_chain_a_session():
    ports = {f.evidence["port"] for f in analyze(LAB / "chainB-run1.pcap").threats if f.rule == "c2"}
    assert ports == {4444, 5555}


@pytest.mark.parametrize("name", ["baseline-clean-full.pcap", "chainA-recon.pcap",
                                  "chainA-exploitation.pcap", "chainB-clean.pcap", "chainA-run1.pcap"])
def test_checksum_offload_is_attributed_to_the_capture_host(name):
    sensor = [f for f in analyze(LAB / name).sensor_findings if "checksum" in f.title]
    assert [f.src for f in sensor] == [ATTACKER]
