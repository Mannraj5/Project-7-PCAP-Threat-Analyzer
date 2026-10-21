# pcapscope report - `chainA-run1.pcap`

| | |
|---|---|
| SHA-256 | `7f0083762bf4012d37e3288a3e9dc3d6c3f3324b70aa3442aacbb3e67f50022b` |
| Packets | 134,478 |
| Bytes on the wire | 9,289,242 (8.9 MB) |
| First packet | 2026-08-12 14:04:44 UTC |
| Last packet | 2026-08-13 03:28:30 UTC |
| Duration | 48,225.8 s |
| Decode errors | 0 |
| Threat findings | 3 |
| Sensor-health findings | 2 |

## Threat findings

### 1. [HIGH] TCP port scan of 192.168.56.20

192.168.56.10 sent SYN probes to 65,535 distinct ports on 192.168.56.20 in 79.0s (830 ports/s); 10 answered SYN-ACK.

- **Rule:** `port-scan`
- **Seen:** 2026-08-12 14:05:25 UTC -> 2026-08-12 14:06:44 UTC
- **Sample frames:** 523, 524, 525, 526, 527 (Wireshark: `frame.number in {523 524 525 526 527}`)
- **Ports probed:** 65535
- **Open ports:** `22`, `135`, `139`, `445`, `49152`, `49153`, `49154`, `49155`, `49156`, `49157`
- **Duration (s):** 78.981
- **Ports per second:** 829.8

### 2. [HIGH] Session on port 4444 (Metasploit default handler)

192.168.56.20 -> 192.168.56.10:4444, 303 packets, 116,010 B sent / 1,077,168 B received over 382.5s.

- **Rule:** `c2`
- **Seen:** 2026-08-13 03:21:19 UTC -> 2026-08-13 03:27:42 UTC
- **Sample frames:** 134137, 134138, 134139, 134140, 134141 (Wireshark: `frame.number in {134137 134138 134139 134140 134141}`)
- **Port:** 4444
- **Reason:** `Metasploit default handler`
- **Packets:** 303
- **Bytes client to server:** 116,010
- **Bytes server to client:** 1,077,168

### 3. [MEDIUM] ARP host sweep from 192.168.56.10

192.168.56.10 probed 255 distinct addresses with ARP over 48057.9s.

- **Rule:** `host-sweep`
- **Seen:** 2026-08-12 14:04:44 UTC -> 2026-08-13 03:25:42 UTC
- **Sample frames:** 1, 3, 4, 5, 6 (Wireshark: `frame.number in {1 3 4 5 6}`)
- **Method:** `ARP`
- **Hosts probed:** 255
- **Sample targets:** `192.168.56.0`, `192.168.56.1`, `192.168.56.2`, `192.168.56.3`, `192.168.56.4`, `192.168.56.5`, `192.168.56.6`, `192.168.56.7`, `192.168.56.8`, `192.168.56.9`, `192.168.56.11`, `192.168.56.12`, `192.168.56.13`, `192.168.56.14`, `192.168.56.15`, `192.168.56.16`, `192.168.56.17`, `192.168.56.18`, `192.168.56.19`, `192.168.56.20`

## Capture health

Properties of the capture that cause other tools to under-report.

### 1. [MEDIUM] Invalid checksums on packets from 192.168.56.10 (likely checksum offload)

565 of 66,469 TCP/UDP/ICMP packets from 192.168.56.10 (1%) carry an invalid checksum. Bad checksums concentrated on one host are what a capture taken on that host looks like when the NIC computes checksums after capture. IDS engines that verify checksums (Snort, Suricata by default) will discard these packets unseen.

- **Rule:** `capture-health`
- **Seen:** 2026-08-12 14:05:26 UTC -> 2026-08-13 03:27:42 UTC
- **Sample frames:** 1063, 131944, 131945, 131947, 131949 (Wireshark: `frame.number in {1063 131944 131945 131947 131949}`)
- **Bad:** 565
- **Checked:** 66,469
- **Ratio:** 0.009
- **Remedy:** `disable checksum validation (Snort: checksum_eval = 'none'; Suricata: -k none) or capture with offload off / out of band`

### 2. [MEDIUM] Frames larger than the Ethernet MTU (segmentation offload)

68 frames exceed 1514 bytes (largest 32,822 B), mostly from 192.168.56.10 (59), 192.168.56.20 (9). Tools reading with a default 1518-byte snaplen will truncate them and may reject them as malformed.

- **Rule:** `capture-health`
- **Seen:** 2026-08-13 03:21:10 UTC -> 2026-08-13 03:27:40 UTC
- **Sample frames:** 134130, 134141, 134142, 134144, 134145 (Wireshark: `frame.number in {134130 134141 134142 134144 134145}`)
- **Count:** 68
- **Largest:** 32,822
- **Remedy:** `raise the reader's snaplen (Snort: -s 65535) or disable TSO/GSO/GRO`

## Traffic overview

### Protocol mix

| Protocol | Packets | Share |
|---|---:|---:|
| tcp | 132,507 | 98.5% |
| arp | 562 | 0.4% |
| dns | 368 | 0.3% |
| icmpv6 | 358 | 0.3% |
| udp | 352 | 0.3% |
| ipv4 | 331 | 0.2% |

### Top talkers (bytes sent)

| Host | Bytes |
|---|---:|
| 192.168.56.10 | 4,972,133 |
| 192.168.56.20 | 4,096,238 |
| 192.168.56.1 | 106,008 |
| fe80::49f0:4046:2879:1ad4 | 100,087 |
| fe80::256b:4013:4140:453f | 13,650 |
| fe80::7b8:9c3e:8aab:7135 | 868 |
| 0.0.0.0 | 180 |
| :: | 78 |

### Top conversations

| Host A | Host B | Service | Bytes |
|---|---|---|---:|
| 192.168.56.10 | 192.168.56.20 | tcp/4444 | 1,210,096 |
| 192.168.56.10 | 192.168.56.20 | tcp/60680 | 571,628 |
| fe80::49f0:4046:2879:1ad4 | ff02::c | udp/3702 | 50,908 |
| 192.168.56.1 | 239.255.255.250 | udp/3702 | 49,368 |
| 192.168.56.1 | 192.168.56.255 | udp/138 (netbios-dgm) | 16,281 |
| fe80::256b:4013:4140:453f | ff02::1:2 | udp/546 | 10,430 |
| fe80::49f0:4046:2879:1ad4 | ff02::1:3 | udp/5355 (llmnr) | 9,947 |
| 192.168.56.10 | 192.168.56.20 | tcp/80 (http) | 9,022 |
| fe80::49f0:4046:2879:1ad4 | ff02::fb | udp/5353 (mdns) | 7,892 |
| 192.168.56.1 | 224.0.0.252 | udp/5355 (llmnr) | 7,687 |

### Top DNS queries

| Name | Queries |
|---|---:|
| `mannraj5` | 220 |
| `_googlecast._tcp.local` | 42 |
| `mannraj5._dosvc._tcp.local` | 24 |
| `appassets.local` | 20 |
| `isatap` | 20 |
| `ie8win7` | 8 |
| `_dosvc._tcp.local` | 6 |
| `appassets` | 6 |

_Generated by pcapscope in 2.62 s._
