"""
Packet parsing and field extraction utilities.

Extracts structured information from packets including:
- Timestamps, source/destination IPs and ports
- Protocol stack
- TCP flags, DNS queries, HTTP headers
- Payload data
- Hex dump generation
"""

from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
import re


class ParsedPacket:
    """Represents extracted packet information."""
    
    def __init__(self):
        self.timestamp: Optional[float] = None
        self.timestamp_iso: Optional[str] = None
        self.summary: str = ""
        self.layers: List[str] = []  # e.g., ["Ether", "IP", "TCP"]
        self.link_type: Optional[str] = None  # Top-level link type (e.g., Ether, Loopback, Radio)
        self.src_ip: Optional[str] = None
        self.dst_ip: Optional[str] = None
        self.src_mac: Optional[str] = None
        self.dst_mac: Optional[str] = None
        self.l4_proto: Optional[str] = None  # TCP, UDP, ICMP, etc.
        self.sport: Optional[int] = None
        self.dport: Optional[int] = None
        self.tcp_flags: List[str] = []  # e.g., ["SYN", "ACK"]
        self.dns_queries: List[str] = []
        self.http_host: Optional[str] = None
        self.http_path: Optional[str] = None
        self.raw_bytes: bytes = b""
        self.payload_bytes: bytes = b""


def extract_packet_info(packet: Any) -> ParsedPacket:
    """
    Extract detailed information from a Scapy packet.
    
    Args:
        packet: A Scapy packet object
    
    Returns:
        ParsedPacket with extracted fields
    """
    parsed = ParsedPacket()
    
    # Timestamp
    if hasattr(packet, "time"):
        try:
            parsed.timestamp = float(packet.time)
            parsed.timestamp_iso = datetime.fromtimestamp(parsed.timestamp).isoformat()
        except (TypeError, ValueError):
            parsed.timestamp = None
            parsed.timestamp_iso = None
    
    # Raw bytes
    try:
        parsed.raw_bytes = bytes(packet)
    except Exception:
        parsed.raw_bytes = b""
    
    # Layer stack
    parsed.layers = _extract_layer_names(packet)
    # Top-level link type (first layer name) - helpful for non-Ethernet PCAPs
    try:
        parsed.link_type = parsed.layers[0] if parsed.layers else None
    except Exception:
        parsed.link_type = None
    
    # MAC addresses (Ethernet layer)
    parsed.src_mac, parsed.dst_mac = _extract_mac_addresses(packet)
    
    # IP addresses
    parsed.src_ip, parsed.dst_ip = _extract_ips(packet)
    
    # L4 protocol and ports
    parsed.l4_proto = _extract_l4_proto(packet)
    parsed.sport, parsed.dport = _extract_ports(packet)
    parsed.tcp_flags = _extract_tcp_flags(packet)
    
    # DNS info
    parsed.dns_queries = _extract_dns_queries(packet)
    
    # HTTP info
    parsed.http_host, parsed.http_path = _extract_http_info(packet)
    
    # Payload bytes
    parsed.payload_bytes = _extract_payload(packet)
    
    # Summary string
    parsed.summary = _build_summary(parsed)
    
    return parsed


def _extract_layer_names(packet: Any) -> List[str]:
    """Extract the layer stack names."""
    layers = []
    try:
        # Scapy packets have a 'layers' method in newer versions, or we can walk the chain
        current = packet
        while current:
            if hasattr(current, "name"):
                layers.append(current.name)
            current = current.payload if hasattr(current, "payload") else None
    except Exception:
        pass
    
    return layers if layers else ["Unknown"]


def _extract_mac_addresses(packet: Any) -> Tuple[Optional[str], Optional[str]]:
    """Extract source and destination MAC addresses."""
    try:
        from scapy.layers.l2 import Ether
        
        if packet.haslayer(Ether):
            eth = packet[Ether]
            return eth.src, eth.dst
    except Exception:
        pass
    
    return None, None


def _extract_ips(packet: Any) -> Tuple[Optional[str], Optional[str]]:
    """Extract source and destination IP addresses (IPv4 or IPv6)."""
    try:
        from scapy.layers.inet import IP
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            return ip_layer.src, ip_layer.dst
    except Exception:
        pass
    
    # Try IPv6
    try:
        from scapy.layers.inet6 import IPv6
        
        if packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            return ipv6_layer.src, ipv6_layer.dst
    except Exception:
        pass
    
    return None, None


def _extract_l4_proto(packet: Any) -> Optional[str]:
    """Extract Layer 4 protocol type."""
    try:
        from scapy.layers.inet import TCP, UDP, ICMP
        
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
    except Exception:
        pass
    
    return None


def _extract_ports(packet: Any) -> Tuple[Optional[int], Optional[int]]:
    """Extract source and destination ports."""
    try:
        from scapy.layers.inet import TCP, UDP
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return tcp_layer.sport, tcp_layer.dport
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            return udp_layer.sport, udp_layer.dport
    except Exception:
        pass
    
    return None, None


def _extract_tcp_flags(packet: Any) -> List[str]:
    """Extract TCP flags."""
    flags = []
    try:
        from scapy.layers.inet import TCP
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            # TCP flags: F=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG, E=ECE, C=CWR
            if tcp_layer.flags.F:
                flags.append("FIN")
            if tcp_layer.flags.S:
                flags.append("SYN")
            if tcp_layer.flags.R:
                flags.append("RST")
            if tcp_layer.flags.P:
                flags.append("PSH")
            if tcp_layer.flags.A:
                flags.append("ACK")
            if tcp_layer.flags.U:
                flags.append("URG")
            if tcp_layer.flags.E:
                flags.append("ECE")
            if tcp_layer.flags.C:
                flags.append("CWR")
    except Exception:
        pass
    
    return flags


def _extract_dns_queries(packet: Any) -> List[str]:
    """Extract DNS query names."""
    queries = []
    try:
        from scapy.layers.dns import DNS, DNSQR
        
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qd:
                # Walk through questions
                qd = dns_layer.qd
                if isinstance(qd, DNSQR):
                    # Single question
                    queries.append(qd.qname.decode("utf-8", errors="ignore").rstrip("."))
                else:
                    # Multiple questions (rare)
                    for q in qd:
                        if hasattr(q, "qname"):
                            queries.append(q.qname.decode("utf-8", errors="ignore").rstrip("."))
    except Exception:
        pass
    
    return queries


def _extract_http_info(packet: Any) -> Tuple[Optional[str], Optional[str]]:
    """Extract HTTP Host and Request-Path from payload."""
    host = None
    path = None
    
    try:
        payload = _extract_payload(packet)
        if payload:
            payload_str = payload.decode("utf-8", errors="ignore")
            
            # Match HTTP request line: GET|POST|HEAD ... HTTP/1.x
            request_match = re.search(r"^(GET|POST|HEAD|PUT|DELETE)\s+(\S+)\s+HTTP/", payload_str, re.MULTILINE)
            if request_match:
                path = request_match.group(2)
            
            # Match Host header
            host_match = re.search(r"Host:\s*([^\r\n]+)", payload_str, re.IGNORECASE)
            if host_match:
                host = host_match.group(1).strip()
    except Exception:
        pass
    
    return host, path


def _extract_payload(packet: Any) -> bytes:
    """Extract Layer 4 payload bytes."""
    try:
        from scapy.layers.inet import TCP, UDP
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return bytes(tcp_layer.payload) if tcp_layer.payload else b""
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            return bytes(udp_layer.payload) if udp_layer.payload else b""
    except Exception:
        pass
    
    return b""


def _build_summary(parsed: ParsedPacket) -> str:
    """Build a human-readable summary of the packet."""
    if parsed.src_ip and parsed.dst_ip:
        base = f"{parsed.src_ip} -> {parsed.dst_ip}"
        
        if parsed.l4_proto:
            base += f" ({parsed.l4_proto})"
            
            if parsed.sport and parsed.dport:
                base += f" {parsed.sport}->{parsed.dport}"
            
            if parsed.dns_queries:
                base += f" DNS: {', '.join(parsed.dns_queries[:2])}"
            
            if parsed.http_host:
                base += f" HTTP: {parsed.http_host}"
        
        return base
    
    return " ".join(parsed.layers)


def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """
    Generate a hex dump of bytes.
    
    Format:
        00000000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
    
    Args:
        data: Bytes to dump
        offset: Starting offset (for display)
        width: Bytes per line (default 16)
    
    Returns:
        Formatted hex dump string
    """
    if not data:
        return ""
    
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex to fixed width
        hex_part = f"{hex_part:<{width * 3}}"
        
        # ASCII part
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." 
            for b in chunk
        )
        
        addr = offset + i
        line = f"{addr:08x}  {hex_part}  {ascii_part}"
        lines.append(line)
    
    return "\n".join(lines)


def hex_to_text(data: bytes) -> str:
    """
    Convert raw bytes to human-readable text format.
    
    Shows:
    - Decoded ASCII/UTF-8 text (where printable)
    - Line breaks shown as [LF] or [CR]
    - Non-printable bytes shown as [XX] in hex
    - Hex dump with ASCII on the right
    
    Args:
        data: Raw bytes to decode
    
    Returns:
        Human-readable text representation
    """
    if not data:
        return "(empty)"
    
    result = []
    
    # Try UTF-8 decode
    try:
        decoded = data.decode('utf-8', errors='replace')
        result.append("=== DECODED TEXT (UTF-8) ===")
        result.append(decoded[:500])  # First 500 chars
        if len(decoded) > 500:
            result.append(f"\n... ({len(decoded)} total characters)")
        result.append("")
    except Exception:
        pass
    
    # Show ASCII version (printable only)
    result.append("=== ASCII (Printable Only) ===")
    ascii_str = ""
    for b in data:
        if 32 <= b < 127:  # Printable ASCII
            ascii_str += chr(b)
        elif b == 10:
            ascii_str += "[LF]"
        elif b == 13:
            ascii_str += "[CR]"
        elif b == 9:
            ascii_str += "[TAB]"
        else:
            ascii_str += f"[{b:02x}]"
    
    result.append(ascii_str[:500])
    if len(ascii_str) > 500:
        result.append(f"... ({len(ascii_str)} characters)")
    result.append("")
    
    # Show hex dump
    result.append("=== HEX DUMP ===")
    result.append(hexdump(data))
    
    return "\n".join(result)

