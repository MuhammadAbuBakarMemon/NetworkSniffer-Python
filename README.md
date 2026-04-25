# PyPacketScope — Low-Level Network Packet Analyzer

> A raw-socket, zero-dependency network sniffer built in pure Python. Operates at the Ethernet frame level, manually unpacking every protocol header byte-by-byte using Python's `struct` module — no Scapy, no libpcap, no abstractions.

---

## ⚠️ Disclaimer

This tool is developed **strictly for educational purposes** — to understand how network protocols work at the byte level, how packet sniffers are built, and how raw sockets interact with the Linux kernel.

**Do not use this tool on any network you do not own or have explicit written permission to monitor.** Unauthorized interception of network traffic is illegal under computer fraud and wiretapping laws in most jurisdictions, including but not limited to the Computer Fraud and Abuse Act (CFAA, US), the Computer Misuse Act (UK), and equivalent legislation worldwide.

The author assumes **no liability** for misuse of this software.

---

## Overview

PyPacketScope opens a raw `AF_PACKET` socket directly against a network interface, pulling every Ethernet frame off the wire before the kernel's network stack processes it. Each captured frame is then dissected layer by layer — Ethernet → IPv4 → TCP / UDP / ICMP — using Python's `struct.unpack()` against known protocol header layouts defined in their respective RFCs.

The result is a terminal-based packet analyzer that gives you full visibility into the byte-level structure of live network traffic, printed in a Wireshark-style hex dump format.

---

## Features

- **Layer 2 — Ethernet:** Unpacks destination MAC, source MAC, and EtherType from the 14-byte Ethernet II frame header
- **Layer 3 — IPv4:** Extracts version, IHL (with variable header length support), TTL, protocol number, checksum, and source/destination IPs; correctly handles `IHL > 5` (options present)
- **Layer 4 — TCP:** Unpacks source/destination ports, sequence number, acknowledgment number, data offset, all 9 control flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR), and window size
- **Layer 4 — UDP:** Unpacks ports, datagram length, and checksum from the fixed 8-byte header
- **Layer 4 — ICMP:** Decodes type, code, and checksum with human-readable type names (Echo Request, TTL Exceeded, Destination Unreachable, etc.)
- **Hex dump output:** Wireshark / `xxd`-style hex dump with offset column, hex column, and printable ASCII side-by-side
- **Promiscuous mode:** Pushes the NIC into promiscuous mode via `ioctl(SIOCSIFFLAGS)` to capture frames not addressed to the host MAC
- **Graceful error handling:** Malformed / truncated packets (`struct.error`) are logged and skipped without crashing the capture loop; `KeyboardInterrupt` triggers a clean exit and socket teardown
- **Zero external dependencies:** Pure Python standard library only — `socket`, `struct`, `fcntl`

---

## Architecture

```
network_sniffer/
├── sniffer.py        # Entry point — capture loop, protocol dispatch, main()
├── socket_init.py    # Raw socket creation, promiscuous mode via ioctl
├── unpacker.py       # struct unpacking for Ethernet, IPv4, TCP, UDP, ICMP
├── display.py        # Terminal output formatters and hex dump
└── utils.py          # MAC formatting, IP conversion, TCP flag parsing
```

---

## How It Works

### The Raw Socket

```python
socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
```

`AF_PACKET` instructs the kernel to deliver complete Ethernet frames directly to userspace, bypassing the TCP/IP stack entirely. `ETH_P_ALL` (`0x0003`) captures every EtherType. This requires `CAP_NET_RAW` — see [Prerequisites](#prerequisites).

---

### Layer 2 — Ethernet Frame (14 bytes)

```
Byte offset:  0        6        12   14
              ┌────────┬────────┬────┬──────────────────┐
              │ DST MAC│ SRC MAC│Type│    Payload...     │
              │ 6 bytes│ 6 bytes│ 2B │                   │
              └────────┴────────┴────┴──────────────────┘
```

```python
dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", raw_frame[:14])
```

`!` enforces big-endian (network byte order). `6s` reads 6 raw bytes (a MAC address). `H` reads a 2-byte unsigned short (EtherType). The EtherType field dispatches to the correct L3 handler: `0x0800` → IPv4, `0x0806` → ARP, `0x86DD` → IPv6.

---

### Layer 3 — IPv4 Header (20–60 bytes)

```
Byte offset:  0      1      2      4      6      8    9    10     12     16     20
              ┌──────┬──────┬──────┬──────┬──────┬────┬────┬──────┬──────┬──────┐
              │Ver+  │DSCP  │Total │ ID   │Flags │TTL │Pro-│Check-│ SRC  │ DST  │
              │ IHL  │      │ Len  │      │+Frag │    │to  │ sum  │  IP  │  IP  │
              │  1B  │  1B  │  2B  │  2B  │  2B  │ 1B │ 1B │  2B  │  4B  │  4B  │
              └──────┴──────┴──────┴──────┴──────┴────┴────┴──────┴──────┴──────┘
```

```python
ver_ihl, dscp, total_len, pkt_id, flags_frag, ttl, proto, checksum, src_raw, dst_raw \
    = struct.unpack("!BBHHHBBH4s4s", raw_packet[:20])

version  = ver_ihl >> 4        # upper nibble
ihl      = (ver_ihl & 0x0F)    # lower nibble — header length in 32-bit words
ihl_bytes = ihl * 4            # true byte offset to L4 payload
```

The first byte encodes two sub-byte fields. Bit-shifting (`>> 4`) isolates the upper nibble (IP version); masking (`& 0x0F`) isolates the lower nibble (IHL). `ihl * 4` converts 32-bit word count to bytes — critical for correctly slicing the L4 payload when IP options extend the header beyond 20 bytes.

---

### Layer 4 — TCP Header (20–60 bytes)

```
Byte offset:  0      2      4      8      12       14     16     18     20
              ┌──────┬──────┬──────┬──────┬────────┬──────┬──────┬──────┐
              │ SRC  │ DST  │ SEQ  │ ACK  │Offset  │Window│Check │ URG  │
              │ Port │ Port │  Num │  Num │+Flags  │ Size │  sum │  Ptr │
              │  2B  │  2B  │  4B  │  4B  │   2B   │  2B  │  2B  │  2B  │
              └──────┴──────┴──────┴──────┴────────┴──────┴──────┴──────┘
```

```python
src_port, dst_port, seq, ack, offset_flags, window, checksum, urg \
    = struct.unpack("!HHIIHHHH", raw_segment[:20])

data_offset = (offset_flags >> 12) * 4   # upper 4 bits → header length
flags_raw   = offset_flags & 0x01FF      # lower 9 bits → control flags
```

The 2-byte `offset_flags` field packs the data offset (4 bits) and all 9 TCP control flags (9 bits) into one `unsigned short`. Each flag is extracted by ANDing against its positional bitmask: `SYN = 0x010`, `ACK = 0x080`, `FIN = 0x008`, etc.

---

### Layer 4 — UDP Header (fixed 8 bytes)

```
Byte offset:  0      2      4      6      8
              ┌──────┬──────┬──────┬──────┬──────────────┐
              │ SRC  │ DST  │Length│Check │  Payload...  │
              │ Port │ Port │      │  sum │              │
              │  2B  │  2B  │  2B  │  2B  │              │
              └──────┴──────┴──────┴──────┴──────────────┘
```

UDP's header is intentionally minimal and always exactly 8 bytes — no options, no sequencing, no acknowledgment. `struct.unpack("!HHHH", raw_segment[:8])` is sufficient.

---

## Prerequisites

### Operating System

**Linux only.** `AF_PACKET` raw sockets are a Linux kernel feature. macOS and Windows do not support this socket family. Windows requires Npcap/WinPcap kernel drivers; macOS uses BPF — both are different mechanisms not implemented here.

Tested on: Ubuntu 22.04+, Debian 12+, Kali Linux 2023+

### Python

```
Python 3.8+
```

No external packages required. All modules used (`socket`, `struct`, `fcntl`) are Python standard library.

### Root / CAP_NET_RAW

Opening `AF_PACKET` sockets requires the `CAP_NET_RAW` Linux capability. The kernel enforces this check inside `sock_create()` before allocating the socket. Three valid approaches:

```bash
# Option 1 — sudo (simplest, grants full root)
sudo python3 sniffer.py

# Option 2 — CAP_NET_RAW only (preferred, principle of least privilege)
sudo setcap cap_net_raw+eip sniffer.py
python3 sniffer.py

# Option 3 — run as root (not recommended)
su root && python3 sniffer.py
```

Option 2 is preferred for any non-throwaway deployment: it grants only the specific capability the tool needs without elevating the entire process to UID 0.

---

## Installation

```bash
git clone https://github.com/<your-username>/pypacketscope.git
cd pypacketscope
```

No `pip install` required.

---

## Usage

```bash
# Identify your active network interface first
ip link show

# Edit IFACE in sniffer.py to match (eth0, wlan0, ens33, etc.)
# Then run:
sudo python3 sniffer.py
```

### Example Output

```
[*] Sniffing on eth0 — press Ctrl+C to stop

════════════════════════════════════════════════════════════
  [ETH]  AA:BB:CC:DD:EE:FF → 11:22:33:44:55:66  |  EtherType: 0x0800
  [IP4]  192.168.1.5 → 142.250.74.46  |  Proto: TCP  TTL: 64  IHL: 20B
  [TCP]  52341 → 443  |  Flags: [SYN]  Seq: 3842910233  Ack: 0  Win: 64240
  [PAYLOAD] 0 bytes total (showing 0)

════════════════════════════════════════════════════════════
  [ETH]  AA:BB:CC:DD:EE:FF → 11:22:33:44:55:66  |  EtherType: 0x0800
  [IP4]  192.168.1.5 → 8.8.8.8  |  Proto: UDP  TTL: 64  IHL: 20B
  [UDP]  54312 → 53  |  Length: 29B
  [PAYLOAD] 21 bytes total (showing 21):
    0000  00 01 01 00 00 01 00 00 00 00 00 00 03 77 77 77  |.............www|
    0010  00 00 01 00 01                                   |.....|
```

### Stopping Capture

```
Ctrl+C
```

The `finally` block ensures the raw socket file descriptor is always closed on exit, even if the loop crashes.

---

## Roadmap

- [ ] IPv6 support (`EtherType 0x86DD`, fixed 40-byte header, 128-bit addresses)
- [ ] ARP dissection (`EtherType 0x0806`)
- [ ] BPF-style interface filter (capture only TCP port 80, or only ICMP, etc.)
- [ ] PCAP file export for post-capture analysis in Wireshark
- [ ] DNS payload parser (UDP port 53)
- [ ] HTTP/1.1 payload reconstruction (TCP port 80)

---

## References

- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) — Internet Protocol (IPv4)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) — Transmission Control Protocol (TCP)
- [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) — User Datagram Protocol (UDP)
- [RFC 792](https://datatracker.ietf.org/doc/html/rfc792) — Internet Control Message Protocol (ICMP)
- [IEEE 802.3](https://standards.ieee.org/ieee/802.3) — Ethernet Frame Standard
- Linux `man 7 packet` — AF_PACKET socket documentation
- Linux `man 7 capabilities` — CAP_NET_RAW and Linux capability model

---

## License

MIT License — see `LICENSE` for details.
