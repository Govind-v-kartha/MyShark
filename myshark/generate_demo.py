#!/usr/bin/env python3
"""
Generate a demo PCAP file with synthetic packets for testing MyShark.

Creates packets with various protocols and characteristics to demonstrate
MyShark's filtering and parsing capabilities.
"""

import sys
from pathlib import Path

try:
    from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap, Raw
except ImportError:
    print("Error: scapy not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


def generate_demo_pcap(output_file: str = "samples/demo.pcap"):
    """Generate a demo PCAP file with various packet types."""
    
    packets = []
    
    # HTTP request (TCP port 80)
    http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: MyShark-Demo\r\n\r\n"
    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
            IP(src="192.168.1.100", dst="93.184.216.34") / \
            TCP(sport=54321, dport=80, flags="PA") / \
            Raw(load=http_request)
    packets.append(pkt1)
    
    # DNS query (UDP port 53)
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") / \
            IP(src="192.168.1.101", dst="8.8.8.8") / \
            UDP(sport=12345, dport=53) / \
            DNS(rd=1, qd=DNSQR(qname="google.com"))
    packets.append(pkt2)
    
    # HTTPS request (TCP port 443)
    pkt3 = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
            IP(src="192.168.1.100", dst="142.250.185.46") / \
            TCP(sport=54322, dport=443, flags="S")
    packets.append(pkt3)
    
    # SSH (TCP port 22)
    ssh_banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"
    pkt4 = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
            IP(src="192.168.1.100", dst="10.0.0.50") / \
            TCP(sport=54323, dport=22, flags="PA") / \
            Raw(load=ssh_banner)
    packets.append(pkt4)
    
    # NTP (UDP port 123)
    ntp_payload = bytes([0x24] + [0] * 47)  # Simplified NTP packet
    pkt5 = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
            IP(src="192.168.1.100", dst="91.189.94.4") / \
            UDP(sport=54324, dport=123) / \
            Raw(load=ntp_payload)
    packets.append(pkt5)
    
    # Multiple DNS queries
    for i in range(3):
        domains = ["github.com", "stackoverflow.com", "wikipedia.org"]
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
              IP(src="192.168.1.100", dst="8.8.8.8") / \
              UDP(sport=12346 + i, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=domains[i]))
        packets.append(pkt)
    
    # TCP SYN scan
    for port in [22, 80, 443, 3306, 5432]:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
              IP(src="192.168.1.100", dst="10.0.0.1") / \
              TCP(sport=50000 + port, dport=port, flags="S")
        packets.append(pkt)
    
    # UDP traffic
    for port in [5353, 6881, 6882]:  # mDNS, BitTorrent
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
              IP(src="192.168.1.100", dst="192.168.1.255") / \
              UDP(sport=55000 + port, dport=port) / \
              Raw(load=b"UDP test payload")
        packets.append(pkt)
    
    # Save to PCAP
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_file, packets)
    
    print(f"Created demo PCAP with {len(packets)} packets: {output_file}")
    print(f"\nPacket breakdown:")
    print(f"  - HTTP (TCP/80): 1")
    print(f"  - HTTPS (TCP/443): 1")
    print(f"  - SSH (TCP/22): 1")
    print(f"  - NTP (UDP/123): 1")
    print(f"  - DNS (UDP/53): 4")
    print(f"  - TCP SYN scan: 5")
    print(f"  - UDP various: 3")
    print(f"\nExample usage:")
    print(f"  python myshark.py read --pcap {output_file}")
    print(f"  python myshark.py read --pcap {output_file} --custom 'proto:tcp and port:80'")
    print(f"  python myshark.py read --pcap {output_file} --custom 'proto:udp and port:53'")


if __name__ == '__main__':
    generate_demo_pcap()
