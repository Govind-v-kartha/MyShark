#!/usr/bin/env python3
"""Load demo packets and show Web UI API endpoints."""

from pcap_store import PcapStore
from parser import extract_packet_info
from scapy.all import rdpcap
import json

# Load demo PCAP
packets = rdpcap('samples/demo.pcap')
store = PcapStore(maxlen=500)

# Parse and store packets
for pkt in packets:
    info = extract_packet_info(pkt)
    store.append(info, raw_packet=pkt)

print("=" * 60)
print("MyShark Web UI - Demo Data Loaded")
print("=" * 60)
print()

print(f"✓ Loaded {store.length()} packets into storage")
print()

print("First 5 packets:")
for i, pkt in enumerate(store.get_all()[:5]):
    ts = pkt.get("timestamp_iso", "?")[:19]
    proto = pkt.get("l4_proto", "?")
    summary = pkt.get("summary", "")[:50]
    print(f"  [{i}] {ts} | {proto:5} | {summary}")

print()
print("=" * 60)
print("Available Web UI Endpoints:")
print("=" * 60)
print()

endpoints = [
    ("GET /", "Main page - Recent packets table with auto-refresh"),
    ("GET /api/recent?count=50", "JSON: Recent N packets"),
    ("GET /packet/<id>", "HTML: Detailed packet view"),
    ("GET /api/packet/<id>", "JSON: Packet details"),
    ("GET /api/hexdump/<id>", "JSON: Packet hex dump"),
    ("GET /api/stats", "JSON: Capture statistics"),
]

for method_path, description in endpoints:
    print(f"  {method_path:<30} - {description}")

print()
print("=" * 60)
print("Example API Calls:")
print("=" * 60)
print()

# Test API endpoints
print("Testing /api/recent endpoint...")
try:
    from web_ui import create_app
    app = create_app(store)
    with app.test_client() as client:
        resp = client.get('/api/recent?count=5')
        data = json.loads(resp.data)
        print(f"  ✓ /api/recent returned {data['total']} total packets")
        print(f"  ✓ Recent packets in response: {len(data['recent'])}")
        if data['recent']:
            p = data['recent'][0]
            print(f"    - Packet 0: {p['timestamp'][:19]} | {p['proto']} | {p['ip_src']} → {p['ip_dst']}")
except Exception as e:
    print(f"  ✗ Error: {e}")

print()
print("=" * 60)
print("To use the Web UI:")
print("=" * 60)
print()
print("1. Open your browser: http://127.0.0.1:5000")
print("2. View recent packets in the table")
print("3. Click any packet row to see details + hex dump")
print("4. Use /api/* endpoints for JSON data")
print()
