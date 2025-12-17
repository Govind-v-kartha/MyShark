# MyShark - Network Packet Analyzer

[![CI](https://github.com/Govind-v-kartha/MyShark/actions/workflows/ci.yml/badge.svg)](https://github.com/Govind-v-kartha/MyShark/actions/workflows/ci.yml)

A lightweight Python-based packet analyzer for PCAP files. Load, filter, and analyze network packets with ease.

## Features

- **Load PCAP Files** - Read packet captures from tcpdump, Wireshark, etc.
- **Extract Packet Info** - Get IP addresses, ports, protocols, DNS queries, HTTP headers
- **Filter Packets** - Filter by protocol (TCP/UDP/ICMP), port, IP address
- **View Hex Dumps** - Inspect packet bytes in readable hex format
- **Web Dashboard** - Browse packets in a web interface
- **Python API** - Integrate packet analysis into your scripts

## Installation

```bash
pip install -e .
```

## Quick Start

### View packets from PCAP file

```bash
python -m myshark.cli read "filename.pcapng"
```

### Filter by protocol

```bash
python -m myshark.cli read "filename.pcapng" --custom "proto:udp"
```

### Filter by port

```bash
python -m myshark.cli read "filename.pcapng" --custom "port:80"
```

### Start web dashboard (FastAPI)

```bash
python -m uvicorn web_app:app --host 127.0.0.1 --port 8000 --reload
```

Then open: **http://127.0.0.1:8000**

## Python API

### Load and analyze packets

```python
from myshark.pcap_store import load_pcap
from myshark.parser import extract_packet_info, hexdump

# Load PCAP file
packets = load_pcap('capture.pcapng')

# Analyze first packet
parsed = extract_packet_info(packets[0])

print(f"Source: {parsed.src_ip}:{parsed.sport}")
print(f"Dest:   {parsed.dst_ip}:{parsed.dport}")
print(f"Protocol: {parsed.l4_proto}")

# Show hex dump
print(hexdump(parsed.raw_bytes))
```

### Find specific traffic

```python
# Find DNS queries
for pkt in packets:
    parsed = extract_packet_info(pkt)
    if parsed.dns_queries:
        print(f"DNS: {parsed.dns_queries}")

# Find HTTP traffic
for pkt in packets:
    parsed = extract_packet_info(pkt)
    if parsed.http_host:
        print(f"HTTP: {parsed.http_host}")
```

## Filter Syntax

| Syntax | Example | Meaning |
|--------|---------|---------|
| `proto:TYPE` | `proto:tcp` | Protocol (tcp, udp, icmp, arp) |
| `port:NUM` | `port:80` | Source or dest port |
| `ip:ADDR` | `ip:192.168.1.1` | Source or dest IP |
| `and` | `proto:tcp and port:80` | Both conditions true |
| `or` | `port:80 or port:443` | Either condition true |
| `not` | `not proto:icmp` | Condition false |
| `()` | `(proto:tcp or proto:udp) and port:53` | Grouping |

## Testing

```bash
python -m pytest tests/test_myshark.py -q
```

## Project Structure

```
myshark/
├── __init__.py
├── cli.py           # CLI interface
├── parser.py        # Packet extraction and parsing
├── filters.py       # Packet filtering logic
├── pcap_store.py    # PCAP file loading and storage
└── web_ui.py        # Flask web dashboard

tests/
└── test_myshark.py  # Test suite

templates/           # Web UI templates (HTML)
static/              # Web UI static files (CSS, JS)
```

## Examples

### Find all HTTP traffic
```bash
python -m myshark.cli read capture.pcap --custom "port:80 or port:443"
```

### Find DNS queries from specific IP
```bash
python -m myshark.cli read capture.pcap --custom "ip:192.168.1.100 and port:53"
```

### Find TCP traffic (no UDP)
```bash
python -m myshark.cli read capture.pcap --custom "proto:tcp"
```

### Find SSH/Telnet/RDP traffic
```bash
python -m myshark.cli read capture.pcap --custom "port:22 or port:23 or port:3389"
```

## Requirements

- Python 3.10+
- scapy - Packet manipulation library
- fastapi - Web framework
- uvicorn - ASGI server
- pytest - Testing framework

## License

MIT
