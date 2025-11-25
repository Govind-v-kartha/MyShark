#!/usr/bin/env python3
"""
Simple demo script to show MyShark functionality
Run this to see packet details from PCAP file
"""

import sys
import os

# Avoid importing CLI to prevent conflicts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Direct imports - bypass CLI
from myshark.parser import extract_packet_info, hexdump
from scapy.all import rdpcap

def main():
    # Load PCAP file directly
    pcap_file = "The Ultimate PCAP v20251113.pcapng"
    
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} not found!")
        sys.exit(1)
    
    print(f"Loading packets from: {pcap_file}\n")
    packets = rdpcap(pcap_file)
    
    if not packets:
        print("No packets found!")
        sys.exit(1)
    
    print(f"Total packets: {len(packets)}")
    print("=" * 80)
    
    # Show first 5 packets
    print("\nShowing first 5 packets:\n")
    for i in range(min(5, len(packets))):
        parsed = extract_packet_info(packets[i])
        
        print(f"\n[Packet #{i}]")
        print(f"  Timestamp:    {parsed.timestamp_iso}")
        print(f"  Link Type:    {parsed.link_type}")
        print(f"  Source:       {parsed.src_ip}:{parsed.sport} ({parsed.src_mac})")
        print(f"  Destination:  {parsed.dst_ip}:{parsed.dport} ({parsed.dst_mac})")
        print(f"  Protocol:     {parsed.l4_proto}")
        print(f"  Layers:       {' / '.join(parsed.layers[:4])}")
        
        if parsed.dns_queries:
            print(f"  DNS Queries:  {parsed.dns_queries}")
        
        if parsed.http_host:
            print(f"  HTTP Host:    {parsed.http_host}")
            print(f"  HTTP Path:    {parsed.http_path}")
    
    # Show detailed hex dump of first packet
    print("\n" + "=" * 80)
    print(f"\nDetailed Hex Dump of Packet #0 ({len(packets[0])} bytes):\n")
    parsed = extract_packet_info(packets[0])
    print(hexdump(parsed.raw_bytes))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
