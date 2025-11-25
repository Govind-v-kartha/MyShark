"""
Unit tests for MyShark filters, parser, and utilities.

Tests cover:
- Custom filter expression parsing and evaluation
- Packet field extraction
- Hexdump generation
- PCAP save/load round-trip
"""

import pytest
import tempfile
import os
from datetime import datetime

from myshark.filters import compile_custom, ParseError, Lexer, Parser, Token
from myshark.parser import (
    ParsedPacket, extract_packet_info, hexdump
)
from myshark.pcap_store import PacketBuffer, load_pcap


class TestFilterLexer:
    """Test the filter expression lexer."""
    
    def test_lexer_keywords(self):
        """Test tokenization of keywords."""
        lexer = Lexer("proto:tcp and port:80 or not proto:udp")
        tokens = lexer.tokenize()
        
        assert len(tokens) > 0
        assert any(t.type == "KEYWORD" and t.value == "and" for t in tokens)
        assert any(t.type == "KEYWORD" and t.value == "or" for t in tokens)
        assert any(t.type == "KEYWORD" and t.value == "not" for t in tokens)
    
    def test_lexer_predicates(self):
        """Test tokenization of predicates."""
        lexer = Lexer("proto:tcp port:80 ip:192.168.1.1")
        tokens = lexer.tokenize()
        
        predicates = [t for t in tokens if t.type == "PREDICATE"]
        assert len(predicates) == 3
        assert predicates[0].value == "proto:tcp"
        assert predicates[1].value == "port:80"
        assert predicates[2].value == "ip:192.168.1.1"
    
    def test_lexer_parentheses(self):
        """Test tokenization of parentheses."""
        lexer = Lexer("(proto:tcp and port:80) or proto:udp")
        tokens = lexer.tokenize()
        
        parens = [t for t in tokens if t.type in ["LPAREN", "RPAREN"]]
        assert len(parens) == 2
        assert parens[0].type == "LPAREN"
        assert parens[1].type == "RPAREN"
    
    def test_lexer_invalid_token(self):
        """Test error handling for invalid tokens."""
        lexer = Lexer("proto:tcp @@@ port:80")
        with pytest.raises(ParseError):
            lexer.tokenize()


class TestFilterParser:
    """Test the filter expression parser."""
    
    def test_parser_simple_predicate(self):
        """Test parsing simple predicate."""
        lexer = Lexer("proto:tcp")
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        filter_func = parser.parse()
        
        assert callable(filter_func)
    
    def test_parser_and_operator(self):
        """Test parsing AND operator."""
        lexer = Lexer("proto:tcp and port:80")
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        filter_func = parser.parse()
        
        assert callable(filter_func)
    
    def test_parser_or_operator(self):
        """Test parsing OR operator."""
        lexer = Lexer("proto:tcp or proto:udp")
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        filter_func = parser.parse()
        
        assert callable(filter_func)
    
    def test_parser_not_operator(self):
        """Test parsing NOT operator."""
        lexer = Lexer("not proto:icmp")
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        filter_func = parser.parse()
        
        assert callable(filter_func)
    
    def test_parser_parentheses(self):
        """Test parsing parenthesized expressions."""
        lexer = Lexer("(proto:tcp and port:80) or proto:udp")
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        filter_func = parser.parse()
        
        assert callable(filter_func)
    
    def test_parser_complex_expression(self):
        """Test parsing complex expressions."""
        expr = "(proto:tcp or proto:udp) and (port:80 or port:443) and not ip:192.168.1.1"
        lexer = Lexer(expr)
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        filter_func = parser.parse()
        
        assert callable(filter_func)


class TestCompileCustom:
    """Test the compile_custom() public API."""
    
    def test_compile_empty_expression(self):
        """Test compiling empty expression returns true filter."""
        filter_func = compile_custom("")
        
        # Should accept any packet
        assert filter_func(None) == True
    
    def test_compile_valid_expression(self):
        """Test compiling valid expression."""
        filter_func = compile_custom("proto:tcp and port:80")
        assert callable(filter_func)
    
    def test_compile_invalid_expression(self):
        """Test compiling invalid expression raises error."""
        with pytest.raises(ParseError):
            compile_custom("proto:invalid_proto")
    
    def test_compile_syntax_error(self):
        """Test compiling syntax errors."""
        with pytest.raises(ParseError):
            compile_custom("proto:tcp and and port:80")


class TestHexdump:
    """Test hexdump generation."""
    
    def test_hexdump_empty(self):
        """Test hexdump of empty data."""
        result = hexdump(b"")
        assert result == ""
    
    def test_hexdump_simple(self):
        """Test hexdump of simple data."""
        data = b"GET / HTTP/1.1\r\n"
        result = hexdump(data)
        
        assert "00000000" in result  # Address
        assert "47 45 54" in result  # "GET" in hex
        assert "GET / HTTP/1.1" in result  # ASCII representation
    
    def test_hexdump_with_offset(self):
        """Test hexdump with non-zero offset."""
        data = b"Hello"
        result = hexdump(data, offset=256)
        
        assert "00000100" in result  # 256 in hex
    
    def test_hexdump_non_printable(self):
        """Test hexdump with non-printable characters."""
        data = b"\x00\x01\x02\x03"
        result = hexdump(data)
        
        assert "00 01 02 03" in result
        assert "...." in result  # Non-printable shown as dots


class TestParsedPacket:
    """Test ParsedPacket data class."""
    
    def test_parsed_packet_initialization(self):
        """Test ParsedPacket initializes correctly."""
        pkt = ParsedPacket()
        
        assert pkt.timestamp is None
        assert pkt.summary == ""
        assert pkt.layers == []
        assert pkt.raw_bytes == b""
        assert pkt.tcp_flags == []
        assert pkt.dns_queries == []


class TestPacketBuffer:
    """Test circular packet buffer."""
    
    def test_buffer_initialization(self):
        """Test buffer initializes with correct maxlen."""
        buf = PacketBuffer(maxlen=100)
        assert buf.maxlen == 100
        assert buf.count() == 0
    
    def test_buffer_append_and_get(self):
        """Test appending and retrieving packets."""
        buf = PacketBuffer(maxlen=10)
        pkt1 = ParsedPacket()
        pkt1.summary = "Packet 1"
        
        buf.append(pkt1)
        
        assert buf.count() == 1
        result = buf.get(0)
        assert result is not None
        assert result[0].summary == "Packet 1"
    
    def test_buffer_circular_behavior(self):
        """Test circular buffer overwrites oldest packets."""
        buf = PacketBuffer(maxlen=3)
        
        # Add 4 packets to a buffer of size 3
        for i in range(4):
            pkt = ParsedPacket()
            pkt.summary = f"Packet {i}"
            buf.append(pkt)
        
        # Should have only 3 packets (newest ones)
        assert buf.count() == 3
    
    def test_buffer_get_recent(self):
        """Test getting recent packets."""
        buf = PacketBuffer(maxlen=10)
        
        for i in range(10):
            pkt = ParsedPacket()
            pkt.summary = f"Packet {i}"
            buf.append(pkt)
        
        recent = buf.get_recent(3)
        assert len(recent) == 3
    
    def test_buffer_clear(self):
        """Test clearing buffer."""
        buf = PacketBuffer(maxlen=10)
        pkt = ParsedPacket()
        buf.append(pkt)
        
        assert buf.count() == 1
        buf.clear()
        assert buf.count() == 0
    
    def test_buffer_save_to_pcap(self):
        """Test saving buffer to PCAP file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = os.path.join(tmpdir, "test.pcap")
            
            buf = PacketBuffer(maxlen=10)
            # Note: We can't easily create real Scapy packets here,
            # but we can test that save returns False for empty buffer
            result = buf.save_to_pcap(pcap_file)
            
            # Empty buffer should return False
            assert result == False


class TestPcapRoundTrip:
    """Test PCAP save and load round-trip."""
    
    def test_pcap_load_invalid_file(self):
        """Test loading invalid PCAP file."""
        result = load_pcap("/nonexistent/file.pcap")
        assert result is None
    
    def test_pcap_roundtrip_with_scapy_packet(self):
        """Test PCAP save/load with real Scapy packet."""
        try:
            from scapy.all import IP, TCP, wrpcap, rdpcap
        except ImportError:
            pytest.skip("Scapy not installed")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = os.path.join(tmpdir, "test.pcap")
            
            # Create a simple packet
            pkt = IP(dst="192.168.1.1") / TCP(dport=80)
            
            # Write and read back
            wrpcap(pcap_file, [pkt])
            packets = rdpcap(pcap_file)
            
            assert len(packets) == 1
            assert packets[0].haslayer(TCP)


class TestFilterEvaluation:
    """Test filter evaluation on synthetic packets."""
    
    def test_filter_proto_tcp(self):
        """Test proto:tcp filter."""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("proto:tcp")
        
        tcp_pkt = IP() / TCP()
        udp_pkt = IP() / UDP()
        
        assert filter_func(tcp_pkt) == True
        assert filter_func(udp_pkt) == False
    
    def test_filter_proto_udp(self):
        """Test proto:udp filter."""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("proto:udp")
        
        tcp_pkt = IP() / TCP()
        udp_pkt = IP() / UDP()
        
        assert filter_func(tcp_pkt) == False
        assert filter_func(udp_pkt) == True
    
    def test_filter_port(self):
        """Test port filter."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("port:80")
        
        pkt_80 = IP() / TCP(dport=80)
        pkt_443 = IP() / TCP(dport=443)
        
        assert filter_func(pkt_80) == True
        assert filter_func(pkt_443) == False
    
    def test_filter_ip(self):
        """Test IP address filter."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("ip:192.168.1.1")
        
        pkt_match = IP(src="192.168.1.1") / TCP()
        pkt_no_match = IP(src="10.0.0.1") / TCP()
        
        assert filter_func(pkt_match) == True
        assert filter_func(pkt_no_match) == False
    
    def test_filter_and_operator(self):
        """Test AND operator."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("proto:tcp and port:80")
        
        tcp_80 = IP() / TCP(dport=80)
        tcp_443 = IP() / TCP(dport=443)
        
        assert filter_func(tcp_80) == True
        assert filter_func(tcp_443) == False
    
    def test_filter_or_operator(self):
        """Test OR operator."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("port:80 or port:443")
        
        pkt_80 = IP() / TCP(dport=80)
        pkt_443 = IP() / TCP(dport=443)
        pkt_8080 = IP() / TCP(dport=8080)
        
        assert filter_func(pkt_80) == True
        assert filter_func(pkt_443) == True
        assert filter_func(pkt_8080) == False
    
    def test_filter_not_operator(self):
        """Test NOT operator."""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        filter_func = compile_custom("not proto:tcp")
        
        tcp_pkt = IP() / TCP()
        udp_pkt = IP() / UDP()
        
        assert filter_func(tcp_pkt) == False
        assert filter_func(udp_pkt) == True


class TestNonEthernetFrames:
    """Test parsing of non-Ethernet link types (IPv6, 802.3, etc.)."""
    
    def test_ipv6_packet_parsing(self):
        """Test parsing IPv6 packets (no Ethernet layer)."""
        try:
            from scapy.all import IPv6, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        # IPv6 packet without Ethernet
        ipv6_pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=443, dport=80)
        parsed = extract_packet_info(ipv6_pkt)
        
        # Should detect that we don't have Ethernet
        assert parsed.link_type != "Ether"
        # Should still extract IPs and ports
        assert parsed.src_ip == "2001:db8::1"
        assert parsed.dst_ip == "2001:db8::2"
        assert parsed.sport == 443
        assert parsed.dport == 80
        assert parsed.l4_proto == "TCP"
    
    def test_ipv4_only_packet_parsing(self):
        """Test parsing IP-only packets (no MAC layer)."""
        try:
            from scapy.all import IP, UDP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        # IP packet without Ethernet
        ip_pkt = IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=53, dport=53)
        parsed = extract_packet_info(ip_pkt)
        
        # Should have detected layer type
        assert parsed.link_type is not None
        # Should extract IPs and ports
        assert parsed.src_ip == "192.168.1.1"
        assert parsed.dst_ip == "8.8.8.8"
        assert parsed.sport == 53
        assert parsed.dport == 53
        assert parsed.l4_proto == "UDP"
        # MAC should be None since no Ethernet layer
        assert parsed.src_mac is None
        assert parsed.dst_mac is None
    
    def test_link_type_detection(self):
        """Test that link_type field is populated correctly."""
        try:
            from scapy.all import Ether, IP, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        # Ethernet packet
        eth_pkt = Ether() / IP() / TCP()
        parsed_eth = extract_packet_info(eth_pkt)
        assert parsed_eth.link_type == "Ethernet"
        
        # IP-only packet (no Ethernet)
        ip_pkt = IP() / TCP()
        parsed_ip = extract_packet_info(ip_pkt)
        # First layer should not be Ethernet
        assert parsed_ip.link_type != "Ethernet"
    
    def test_ethernet_with_ipv6(self):
        """Test Ethernet frame containing IPv6."""
        try:
            from scapy.all import Ether, IPv6, TCP
        except ImportError:
            pytest.skip("Scapy not installed")
        
        eth_ipv6_pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=22, dport=22)
        parsed = extract_packet_info(eth_ipv6_pkt)
        
        assert parsed.link_type == "Ethernet"
        assert parsed.src_ip == "fe80::1"
        assert parsed.dst_ip == "fe80::2"
        assert parsed.sport == 22
        assert parsed.dport == 22
        assert parsed.l4_proto == "TCP"

