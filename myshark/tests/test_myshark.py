"""
Unit tests for MyShark filter parser and packet parsing.

Tests:
- Custom filter parser (operators, parentheses, precedence)
- Parser extraction functions
- Hexdump correctness
- PCAP save/read round trip
"""

import pytest
import tempfile
import os
from unittest.mock import Mock
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap, rdpcap

# Import modules to test
from filters import (
    tokenize, compile_custom, FilterParseError, is_valid_ipv4,
    create_proto_predicate, create_port_predicate, create_ip_predicate
)
from parser import (
    extract_packet_info, hexdump, extract_tcp_flags, 
    extract_dns_info, extract_http_info, get_layer_stack
)
from pcap_store import PcapStore


# ============================================================================
# Filter Parser Tests
# ============================================================================

class TestFilterTokenizer:
    """Test the tokenizer for filter expressions."""
    
    def test_tokenize_simple_predicate(self):
        """Test tokenizing a simple predicate."""
        tokens = tokenize("proto:tcp")
        assert tokens == ["proto:tcp"]
    
    def test_tokenize_with_and(self):
        """Test tokenizing with and operator."""
        tokens = tokenize("proto:tcp and port:80")
        assert tokens == ["proto:tcp", "and", "port:80"]
    
    def test_tokenize_with_or(self):
        """Test tokenizing with or operator."""
        tokens = tokenize("proto:udp or proto:tcp")
        assert tokens == ["proto:udp", "or", "proto:tcp"]
    
    def test_tokenize_with_not(self):
        """Test tokenizing with not operator."""
        tokens = tokenize("not proto:icmp")
        assert tokens == ["not", "proto:icmp"]
    
    def test_tokenize_with_parentheses(self):
        """Test tokenizing with parentheses."""
        tokens = tokenize("(proto:tcp and port:80) or port:443")
        assert tokens == ["(", "proto:tcp", "and", "port:80", ")", "or", "port:443"]
    
    def test_tokenize_whitespace_handling(self):
        """Test tokenizer handles extra whitespace."""
        tokens = tokenize("  proto:tcp  and  port:80  ")
        assert tokens == ["proto:tcp", "and", "port:80"]


class TestFilterPredicates:
    """Test individual predicate creation."""
    
    def test_proto_predicate_tcp(self):
        """Test protocol predicate for TCP."""
        pred = create_proto_predicate("tcp")
        assert pred({'l4_proto': 'TCP'}) == True
        assert pred({'l4_proto': 'UDP'}) == False
    
    def test_proto_predicate_case_insensitive(self):
        """Test protocol predicate is case insensitive."""
        pred = create_proto_predicate("TCP")
        assert pred({'l4_proto': 'tcp'}) == True
    
    def test_proto_predicate_invalid(self):
        """Test invalid protocol raises error."""
        with pytest.raises(FilterParseError):
            create_proto_predicate("invalid")
    
    def test_port_predicate_src(self):
        """Test port predicate matches source port."""
        pred = create_port_predicate("80")
        assert pred({'sport': 80, 'dport': 443}) == True
    
    def test_port_predicate_dst(self):
        """Test port predicate matches destination port."""
        pred = create_port_predicate("443")
        assert pred({'sport': 80, 'dport': 443}) == True
    
    def test_port_predicate_no_match(self):
        """Test port predicate when no match."""
        pred = create_port_predicate("8080")
        assert pred({'sport': 80, 'dport': 443}) == False
    
    def test_port_predicate_invalid_number(self):
        """Test invalid port number raises error."""
        with pytest.raises(FilterParseError):
            create_port_predicate("invalid")
    
    def test_port_predicate_out_of_range(self):
        """Test port out of range raises error."""
        with pytest.raises(FilterParseError):
            create_port_predicate("99999")
    
    def test_ip_predicate_src(self):
        """Test IP predicate matches source."""
        pred = create_ip_predicate("192.168.1.1")
        assert pred({'ip_src': '192.168.1.1', 'ip_dst': '8.8.8.8'}) == True
    
    def test_ip_predicate_dst(self):
        """Test IP predicate matches destination."""
        pred = create_ip_predicate("8.8.8.8")
        assert pred({'ip_src': '192.168.1.1', 'ip_dst': '8.8.8.8'}) == True
    
    def test_ip_predicate_invalid(self):
        """Test invalid IP raises error."""
        with pytest.raises(FilterParseError):
            create_ip_predicate("999.999.999.999")


class TestIPValidation:
    """Test IP address validation."""
    
    def test_valid_ipv4(self):
        """Test valid IPv4 address."""
        assert is_valid_ipv4("192.168.1.1") == True
        assert is_valid_ipv4("0.0.0.0") == True
        assert is_valid_ipv4("255.255.255.255") == True
    
    def test_invalid_ipv4_format(self):
        """Test invalid IPv4 formats."""
        assert is_valid_ipv4("192.168.1") == False
        assert is_valid_ipv4("192.168.1.1.1") == False
    
    def test_invalid_ipv4_range(self):
        """Test IPv4 out of range."""
        assert is_valid_ipv4("192.168.256.1") == False
        assert is_valid_ipv4("999.999.999.999") == False
    
    def test_invalid_ipv4_non_numeric(self):
        """Test non-numeric IPv4."""
        assert is_valid_ipv4("192.168.1.x") == False


class TestFilterCompiler:
    """Test filter expression compilation and evaluation."""
    
    def test_compile_simple_proto(self):
        """Test compiling simple proto filter."""
        f = compile_custom("proto:tcp")
        assert f({'l4_proto': 'TCP'}) == True
        assert f({'l4_proto': 'UDP'}) == False
    
    def test_compile_and_expression(self):
        """Test compiling and expression."""
        f = compile_custom("proto:tcp and port:80")
        assert f({'l4_proto': 'TCP', 'sport': 80}) == True
        assert f({'l4_proto': 'TCP', 'sport': 443}) == False
        assert f({'l4_proto': 'UDP', 'sport': 80}) == False
    
    def test_compile_or_expression(self):
        """Test compiling or expression."""
        f = compile_custom("proto:tcp or proto:udp")
        assert f({'l4_proto': 'TCP'}) == True
        assert f({'l4_proto': 'UDP'}) == True
        assert f({'l4_proto': 'ICMP'}) == False
    
    def test_compile_not_expression(self):
        """Test compiling not expression."""
        f = compile_custom("not proto:icmp")
        assert f({'l4_proto': 'TCP'}) == True
        assert f({'l4_proto': 'ICMP'}) == False
    
    def test_compile_complex_expression(self):
        """Test compiling complex expression with parentheses."""
        f = compile_custom("(proto:tcp or proto:udp) and port:53")
        assert f({'l4_proto': 'TCP', 'sport': 53}) == True
        assert f({'l4_proto': 'UDP', 'dport': 53}) == True
        assert f({'l4_proto': 'ICMP', 'sport': 53}) == False
        assert f({'l4_proto': 'TCP', 'sport': 80}) == False
    
    def test_compile_empty_filter(self):
        """Test empty filter matches everything."""
        f = compile_custom("")
        assert f({'l4_proto': 'TCP'}) == True
        assert f({}) == True
    
    def test_compile_invalid_syntax(self):
        """Test invalid syntax raises error."""
        with pytest.raises(FilterParseError):
            compile_custom("proto:tcp and")
    
    def test_compile_invalid_operator(self):
        """Test invalid operator raises error."""
        with pytest.raises(FilterParseError):
            compile_custom("proto:tcp xor port:80")


# ============================================================================
# Parser Tests
# ============================================================================

class TestPacketParsing:
    """Test packet parsing and extraction."""
    
    def test_extract_tcp_flags(self):
        """Test TCP flag extraction."""
        # Create a minimal TCP packet with SYN flag
        pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="S")
        tcp_layer = pkt.getlayer(TCP)
        
        flags = extract_tcp_flags(tcp_layer)
        assert flags['SYN'] == True
        assert flags['ACK'] == False
    
    def test_get_layer_stack(self):
        """Test layer stack generation."""
        pkt = Ether() / IP() / TCP()
        stack = get_layer_stack(pkt)
        assert "Ether" in stack
        assert "IP" in stack
        assert "TCP" in stack
    
    def test_extract_ip_packet_info(self):
        """Test extracting IP packet information."""
        pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)
        info = extract_packet_info(pkt)
        
        assert info['ip_src'] == "192.168.1.1"
        assert info['ip_dst'] == "192.168.1.2"
        assert info['sport'] == 12345
        assert info['dport'] == 80
        assert info['l4_proto'] == 'TCP'
    
    def test_extract_udp_packet_info(self):
        """Test extracting UDP packet information."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
        info = extract_packet_info(pkt)
        
        assert info['ip_src'] == "10.0.0.1"
        assert info['ip_dst'] == "10.0.0.2"
        assert info['sport'] == 5000
        assert info['dport'] == 53
        assert info['l4_proto'] == 'UDP'
    
    def test_extract_has_timestamp(self):
        """Test that extracted info has timestamp."""
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        info = extract_packet_info(pkt)
        
        assert 'timestamp' in info
        assert 'timestamp_iso' in info
        assert info['timestamp'] > 0
    
    def test_extract_has_raw_bytes(self):
        """Test that extracted info has raw bytes."""
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        info = extract_packet_info(pkt)
        
        assert 'raw_bytes' in info
        assert len(info['raw_bytes']) > 0


class TestHexdump:
    """Test hex dump generation."""
    
    def test_hexdump_basic(self):
        """Test basic hex dump."""
        data = b"Hello"
        result = hexdump(data)
        
        assert "0000" in result
        assert "Hello" in result
    
    def test_hexdump_multiple_lines(self):
        """Test hex dump with multiple lines."""
        data = b"A" * 32
        result = hexdump(data, length=16)
        
        lines = result.strip().split('\n')
        assert len(lines) == 2
    
    def test_hexdump_with_prefix(self):
        """Test hex dump with prefix."""
        data = b"Test"
        result = hexdump(data, prefix=">> ")
        
        assert ">>" in result
    
    def test_hexdump_empty(self):
        """Test hex dump of empty data."""
        result = hexdump(b"")
        assert "(empty)" in result


# ============================================================================
# Storage Tests
# ============================================================================

class TestPcapStore:
    """Test packet storage functionality."""
    
    def test_store_append(self):
        """Test appending packet info."""
        store = PcapStore(maxlen=10)
        pkt_info = {'timestamp': 1234567890, 'l4_proto': 'TCP'}
        
        idx = store.append(pkt_info)
        assert idx == 0
        assert store.length() == 1
    
    def test_store_get(self):
        """Test retrieving packet info."""
        store = PcapStore(maxlen=10)
        pkt_info = {'timestamp': 1234567890, 'l4_proto': 'TCP'}
        
        store.append(pkt_info)
        retrieved = store.get(0)
        
        assert retrieved == pkt_info
    
    def test_store_circular_buffer(self):
        """Test circular buffer behavior."""
        store = PcapStore(maxlen=3)
        
        for i in range(5):
            store.append({'id': i})
        
        # Should only have last 3
        assert store.length() == 3
    
    def test_store_get_all(self):
        """Test getting all packets."""
        store = PcapStore(maxlen=10)
        
        for i in range(3):
            store.append({'id': i})
        
        all_pkts = store.get_all()
        assert len(all_pkts) == 3
    
    def test_store_clear(self):
        """Test clearing buffer."""
        store = PcapStore(maxlen=10)
        store.append({'id': 1})
        
        store.clear()
        assert store.length() == 0
    
    def test_store_save_to_pcap(self):
        """Test saving packets to pcap file."""
        store = PcapStore(maxlen=10)
        
        # Create and save a test packet
        pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
        info = extract_packet_info(pkt)
        store.append(info, raw_packet=pkt)
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            temp_file = f.name
        
        try:
            store.save_to_pcap(temp_file)
            assert os.path.exists(temp_file)
            assert os.path.getsize(temp_file) > 0
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_store_load_from_pcap(self):
        """Test loading packets from pcap file."""
        # Create a test pcap file
        pkt1 = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP()
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            temp_file = f.name
        
        try:
            wrpcap(temp_file, [pkt1, pkt2])
            
            store = PcapStore(maxlen=10)
            count = store.load_from_pcap(temp_file)
            
            assert count == 2
            assert store.length() == 2
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests combining multiple components."""
    
    def test_filter_with_parsed_packets(self):
        """Test custom filter on parsed packets."""
        # Create test packets
        pkt_tcp = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
        pkt_udp = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5353)
        
        info_tcp = extract_packet_info(pkt_tcp)
        info_udp = extract_packet_info(pkt_udp)
        
        # Compile filter
        f = compile_custom("proto:tcp and port:80")
        
        # Test filter
        assert f(info_tcp) == True
        assert f(info_udp) == False
    
    def test_packet_capture_save_load_cycle(self):
        """Test complete capture, save, and load cycle."""
        # Create test packets
        pkts = [
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5353),
        ]
        
        # Store packets
        store1 = PcapStore(maxlen=10)
        for pkt in pkts:
            info = extract_packet_info(pkt)
            store1.append(info, raw_packet=pkt)
        
        # Save to file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            temp_file = f.name
        
        try:
            store1.save_to_pcap(temp_file)
            
            # Load into new store
            store2 = PcapStore(maxlen=10)
            count = store2.load_from_pcap(temp_file)
            
            assert count == 2
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
