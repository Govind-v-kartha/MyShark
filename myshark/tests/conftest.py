"""
Pytest configuration and fixtures for MyShark tests.
"""

import pytest
import tempfile
import os
from pathlib import Path

# Ensure parent directory is in path so we can import myshark modules
import sys
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


@pytest.fixture
def temp_pcap_file():
    """Create a temporary PCAP file for testing."""
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def sample_packets():
    """Provide sample Scapy packets for testing."""
    try:
        from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR
    except ImportError:
        pytest.skip("Scapy not available")
    
    packets = {
        'tcp': Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443),
        'udp': Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53),
        'dns': Ether() / IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
    }
    return packets
