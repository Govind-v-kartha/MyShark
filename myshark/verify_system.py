#!/usr/bin/env python3
"""End-to-end verification of MyShark system."""

import sys
from pathlib import Path
from scapy.all import rdpcap

# Verify all modules
from filters import compile_custom
from parser import extract_packet_info, hexdump
from pcap_store import PcapStore

print('MyShark - Complete System Verification')
print('=' * 50)
print()

# 1. Load demo PCAP
print('[1] Loading demo PCAP...')
packets = rdpcap('samples/demo.pcap')
print(f'    ✓ Loaded {len(packets)} packets')

# 2. Initialize storage
print('[2] Initializing packet store...')
store = PcapStore(maxlen=500)
print('    ✓ Store created (500 packet capacity)')

# 3. Parse and store packets
print('[3] Parsing and storing packets...')
for pkt in packets:
    info = extract_packet_info(pkt)
    store.append(info, raw_packet=pkt)
print(f'    ✓ Stored {store.length()} packets')

# 4. Test filter compilation
print('[4] Testing filter compilation...')
filter_tests = [
    'proto:tcp',
    'proto:tcp and port:80',
    '(proto:tcp or proto:udp) and port:53',
    'not proto:icmp',
]
for expr in filter_tests:
    f = compile_custom(expr)
    print(f'    ✓ Compiled: {expr}')

# 5. Apply filters to stored packets
print('[5] Applying filters to stored packets...')
all_packets = store.get_all()

f_tcp = compile_custom('proto:tcp')
tcp_count = sum(1 for p in all_packets if f_tcp(p))
print(f'    ✓ TCP packets: {tcp_count}')

f_dns = compile_custom('proto:udp and port:53')
dns_count = sum(1 for p in all_packets if f_dns(p))
print(f'    ✓ DNS packets: {dns_count}')

f_http = compile_custom('proto:tcp and port:80')
http_count = sum(1 for p in all_packets if f_http(p))
print(f'    ✓ HTTP packets: {http_count}')

# 6. Inspect a packet
print('[6] Packet inspection...')
if all_packets:
    pkt = all_packets[0]
    print(f'    ✓ Packet timestamp: {pkt.get("timestamp_iso", "N/A")}')
    print(f'    ✓ Protocol: {pkt.get("l4_proto", "N/A")}')
    if pkt.get('ip_src'):
        print(f'    ✓ IP: {pkt["ip_src"]} → {pkt["ip_dst"]}')
    if pkt.get('sport'):
        print(f'    ✓ Ports: {pkt["sport"]} → {pkt["dport"]}')

# 7. Test PCAP round-trip
print('[7] Testing PCAP save/load cycle...')
import tempfile
import os
with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
    temp_file = f.name

try:
    store.save_to_pcap(temp_file)
    print(f'    ✓ Saved to {temp_file}')
    
    store2 = PcapStore()
    count = store2.load_from_pcap(temp_file)
    print(f'    ✓ Loaded {count} packets from saved file')
finally:
    if os.path.exists(temp_file):
        os.unlink(temp_file)

print()
print('=' * 50)
print('✅ All systems operational!')
