# PCAP Threat Analyzer

**A packet-capture parser and threat analyser written from scratch on the Python standard library — no
libpcap, scapy, dpkt or tshark — validated packet-for-packet against real attack captures.**

`pcapscope` reads classic pcap and pcapng byte by byte, decodes Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP →
DNS/SMB, and runs eight detectors in a single pass. It reports two kinds of finding: **threats** (scans,
exploitation, C2, tunnelling, spoofing, credentials in the clear) and **capture-health** problems that make
other tools silently under-report.

[![tests](https://github.com/Mannraj5/Project-7-PCAP-Threat-Analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Mannraj5/Project-7-PCAP-Threat-Analyzer/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)

---

## The result

Run against the six captures from my [Purple Team Lab](https://github.com/Mannraj5/Project-2-Purple-Team-Lab),
whose packet counts were recorded with `capinfos` and whose attack chains are documented:

| Capture | Packets (`capinfos`) | Packets (`pcapscope`) | Ground truth | Detected |
|---|---:|---:|---|---|
| `baseline-clean-full` | 9,092 | **9,092** | Benign control | **No threat findings** |
| `chainA-recon` | 132,727 | **132,727** | Host discovery, full TCP port scan | ARP sweep of 255 hosts; scan of **65,535 ports** at 830 ports/s, 10 open |
| `chainA-exploitation` | 493 | **493** | HTTP delivery, C2 on 4444 | Session on 4444: 303 packets, 1.08 MB to the victim |
| `chainB-clean` | 563 | **563** | MS17-010, C2 on 5555 | DoublePulsar probe (implant **absent**); session on 5555; SMBv1 session |
| `chainA-run1` | 134,478 | **134,478** | Original of A (13.4 h) | Scan, sweep and the 4444 session — byte-identical to the trimmed capture |
| `chainB-run1` | 581 | **581** | Original of B, with a leftover Chain A session | Everything in B **plus the residual 18-packet 4444 session** |

Every capture is analysed in a single pass; the 132,727-packet scan takes **2.4 s** on a laptop.
These checks run in CI on every push, against the lab captures fetched straight from the Project 2 repository.

Full reports: [`results/lab/`](results/lab/) (Markdown and JSON for each capture).

---

## Three things the packets showed

### 1. The MS17-010 exploit checked for a backdoor before it attacked — and the answer is in one field

Chain B contains two SMBv1 `Trans2 SESSION_SETUP` requests. Legitimate clients never send that subcommand; it
is the control channel of the **DoublePulsar** implant, and MS17-010 exploits use it to ask *"are you already
infected?"* before they run. The question is encoded in the SMB **Multiplex ID**: the probe sends `65`, and an
infected host replies with `65 + 16 = 81`.

```
frame 27  192.168.56.10 -> .20   Trans2 SESSION_SETUP   MID 65   (DoublePulsar ping)
frame 28  192.168.56.20 -> .10   STATUS_NOT_IMPLEMENTED MID 65   (no implant)
```

`pcapscope` reads both sides and reports **"no DoublePulsar implant was present when probed"** — a statement
about the victim's state *before* exploitation that a signature match on the request alone cannot make. The
detector also does not fire on the baseline, where Windows offers the SMBv1 dialect during negotiation and
then moves to SMB2.

### 2. The capture host is identifiable from checksums alone

| Capture | Host | Bad TCP/UDP/ICMP checksums |
|---|---|---:|
| `baseline-clean-full` | 192.168.56.10 | 2,368 / 3,880 (61%) |
| `chainA-exploitation` | 192.168.56.10 | 170 / 170 (100%) |
| `chainB-clean` | 192.168.56.10 | 281 / 283 (99%) |
| `chainA-recon` | 192.168.56.10 | 393 / 66,297 (0.6%) |
| Project 3 `dns-four-transports.pcapng` | 192.168.1.115 | 110 / 110 |

Invalid checksums concentrated on one address are the signature of **transmit checksum offload**: the capture
was taken *on* that host, before its NIC filled the checksum in. It is exactly the failure that made Snort
discard the entire attacker-side payload surface in Project 2 — found there by debugging silent rules, found
here in one pass with no IDS involved. The report names the remedy (`checksum_eval = 'none'`, `-k none`, or an
out-of-band sensor), and flags the oversized TSO/GRO frames (up to **48,234 bytes**) that break a 1518-byte
snaplen.

The recon row is the interesting one: only 0.6% bad. Nmap builds its SYN probes in user space with correct
checksums, so 66,000 good packets dilute the 393 kernel-built ones. A ratio-only rule missed this capture; the
rule now also fires on an absolute count.

### 3. A trimmed capture and its original must agree — and at first they didn't

`chainA-exploitation` is a time-window cut of `chainA-run1`. The first version of the C2 detector reported the
4444 session as **116 KB sent / 1.08 MB received** in the trim, and **116 KB / 0 B** in the original.

The cause: sessions were keyed on *(client, server, server port)*. In the original, the port scan had already
created an entry for every port on the victim — including the ephemeral port the victim later used for its
reverse shell. Shell traffic from the attacker matched that scan entry and was booked to the wrong session.
Connections are now tracked by full 4-tuple, a regression test reproduces the collision synthetically, and a
lab test asserts both captures yield identical numbers (303 packets, 116,010 / 1,077,168 bytes).

---

## What it detects

| Rule | Finds | How |
|---|---|---|
| `port-scan` | Vertical TCP scans | Distinct ports receiving bare SYNs from one source; SYN-ACKs give the open ports |
| `host-sweep` | Host discovery | Distinct targets of ARP requests, ICMP echo or SYNs (ICMP/SYN only within the source's subnet) |
| `c2` | Sessions on offensive-tooling ports | 4444, 5555, 1337, 31337 … — only when data actually flowed, sized by bytes each way |
| `beacon` | Periodic check-ins | Coefficient of variation of connection intervals (≥ 6 connections, mean ≥ 1 s) |
| `smb-exploit` | MS17-010 / DoublePulsar | SMBv1 Trans2 `SESSION_SETUP` + reply Multiplex ID (implant present or not) |
| `smbv1` | Deprecated SMBv1 in use | Successful SMBv1 session setup (negotiation alone is not flagged) |
| `dns-tunnel` | Data exfiltration over DNS | Per-domain unique subdomains, label length, Shannon entropy |
| `arp-spoof` | ARP cache poisoning | One IPv4 address announced by more than one MAC |
| `cleartext-credentials` | FTP, POP3, IMAP, HTTP Basic | Protocol parsing; **passwords are masked** before they reach any report |
| `capture-health` | Checksum offload, TSO/GRO frames, truncation | Per-host checksum verification, frame size vs MTU, caplen vs wire length |

Every finding carries sample frame numbers and a ready-made Wireshark filter
(`frame.number in {27 61}`) so it can be verified by hand.

The lab captures don't contain tunnelling, spoofing, credentials or beaconing, so
[`scripts/make_demo_capture.py`](scripts/make_demo_capture.py) builds a deterministic synthetic incident —
an ARP-poisoned LAN, FTP and HTTP Basic logins, a 30 s beacon and base32 DNS exfiltration — on top of
background traffic. Report: [`results/demo.md`](results/demo.md).

---

## Usage

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

```powershell
pcapscope samples\demo.pcapng
pcapscope capture.pcap --report report.md --json report.json
pcapscope pcaps\*.pcap --report results\        # one report per capture
pcapscope capture.pcap --fail-on high           # exit 2 on a high finding (CI / triage scripts)
```

```
demo.pcapng: 325 packets, 24.8 KB, 589.3 s  [0.01 s to analyse]
  [  HIGH] Conflicting ARP announcements for 10.10.0.1
  [  HIGH] FTP credentials sent in cleartext
  [  HIGH] HTTP Basic credentials sent in cleartext
  [  HIGH] Periodic connections to 203.0.113.77:8443
  [MEDIUM] Possible DNS tunnelling via cdn-telemetry.net
```

Or as a library:

```python
from pcapscope import analyze, read_capture

result = analyze("capture.pcap")
for finding in result.threats:
    print(finding.severity, finding.title, finding.frames)

for frame in read_capture("capture.pcapng"):   # raw frames, any link type
    ...
```

---

## How it works

```
read_capture()            decode()                       detectors (single pass)
 ┌──────────────┐  Frame   ┌──────────────────────┐  Packet  ┌─────────────────────┐
 │ pcap  (4 magics:        │ Ethernet / 802.1Q /   │          │ port-scan  host-sweep│
 │  LE/BE × µs/ns)│───────▶│ SLL / SLL2 / raw IP   │─────────▶│ c2 + beacon  smb     │──▶ findings
 │ pcapng (SHB/IDB│        │ IPv4 (+frag) / IPv6   │          │ dns-tunnel arp-spoof │
 │  /EPB/SPB,     │        │ (+ext hdrs) / ARP     │          │ credentials          │
 │  if_tsresol)   │        │ TCP / UDP / ICMP(v6)  │          │ capture-health       │
 └──────────────┘          │ DNS (compression)     │          └─────────────────────┘
                           └──────────────────────┘          TrafficStats ──▶ report.md / .json
```

| Module | Responsibility |
|---|---|
| [`reader.py`](src/pcapscope/reader.py) | Both file formats, both byte orders, µs/ns and `if_tsresol` timestamps; tolerates captures cut off mid-record |
| [`decode.py`](src/pcapscope/decode.py) | Protocol layers into a flat `Packet`; never raises on malformed input; verifies IP and L4 checksums |
| [`detect.py`](src/pcapscope/detect.py) | Detectors with aggregated state only — memory scales with hosts and ports, not packets |
| [`stats.py`](src/pcapscope/stats.py) | Protocol mix, top talkers, conversations, DNS names |
| [`report.py`](src/pcapscope/report.py) | Markdown, JSON and terminal output |
| [`craft.py`](src/pcapscope/craft.py) | Builds valid frames and pcap/pcapng files byte by byte, for tests and the demo |

Two implementation details worth calling out:

- **Checksums without a loop.** Because `2¹⁶ ≡ 1 (mod 0xFFFF)`, reading a buffer as one big integer and
  reducing it mod `0xFFFF` gives the one's-complement sum of its 16-bit words. Verifying every TCP/UDP checksum
  in 132,727 packets costs one `int.from_bytes` per packet instead of a Python loop over each word.
- **Hostile input.** DNS compression pointers are bounded (a self-referencing pointer cannot hang the
  parser), truncated and fragmented packets are never checksum-verified, and decoding failures are recorded on
  the packet rather than raised.

---

## Testing

```powershell
pytest                                                          # 59 tests, synthetic captures
$env:PCAPSCOPE_LAB_CAPTURES = "..\Project-2-Purple-Team-Lab\pcaps"
pytest                                                          # + 17 checks against the real lab captures
```

- **Reader** — all four pcap magics, pcapng in both byte orders with decimal and binary `if_tsresol`, unknown
  blocks, snaplen truncation, files cut off mid-record.
- **Decoder** — every supported layer, VLAN tags, IPv6, SLL/raw link types, bad checksums, a DNS pointer loop,
  non-first fragments, and arbitrary garbage.
- **Detectors** — a positive *and* a negative case for each rule (e.g. 60 HTTPS connections to 60 servers is
  not a sweep; irregular connections are not a beacon; SMBv1 negotiation alone is not flagged).
- **Lab** — `capinfos` packet counts for all six captures, zero threat findings on the baseline, each documented
  attack found, trim/original consistency, and checksum offload attributed to the capture host.

CI runs the full suite on Ubuntu and Windows across Python 3.10, 3.12 and 3.13, verifies the lab captures'
SHA-256 digests first, and checks that the demo capture regenerates byte-identically.

---

## Limitations

- **Thresholds are heuristics.** Scan, sweep, beacon and tunnel rules count behaviour; a slow scan under 25
  ports, or a beacon with heavy jitter, will not fire. All thresholds are in `Config` and the main ones are CLI
  flags.
- **No TCP reassembly.** Payload rules (credentials, SMB) inspect one segment at a time; a command split across
  segments is missed.
- **Port-based C2 is a hint, not proof.** 4444 and 5555 are defaults that real operators change. The rule's value
  is in sizing the session — refused SYNs are ignored, and severity follows the bytes exchanged.
- **Sweeps across subnets** are not reported by `host-sweep`, the price of not flagging ordinary browsing.
- **`split_domain` uses the last two labels**, not the Public Suffix List, so `x.example.co.uk` groups under
  `co.uk`.
- **Encrypted traffic** is analysed by metadata only (sizes, timing, endpoints).

---

## Related projects

- [Project 1 — Network Forensics](https://github.com/Mannraj5/Project-1-Network-Forensics): flow-level (NetFlow)
  analysis and ML. This project works one layer down, on the packets themselves.
- [Project 2 — Purple Team Lab](https://github.com/Mannraj5/Project-2-Purple-Team-Lab): the attack chains and
  captures used for validation here, and the Snort study whose sensor failures `capture-health` now detects
  directly.
- [Project 3 — Network Protocols Lab](https://github.com/Mannraj5/Project-3-Network-Protocols-Lab): its pcapng
  capture is read by this parser as a format check.

---

## Licence

MIT — see [LICENSE](LICENSE).
