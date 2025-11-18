"""
Packet parsing and extraction helpers.

Extracts structured information from Scapy packets including:
- Timestamp and summary
- Layer stack information
- IP source/destination
- L4 protocol and ports
- TCP flags
- DNS query names
- HTTP host and path
- Raw bytes and payload
"""

import io
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest


logger = logging.getLogger(__name__)


def hexdump(data: bytes, prefix: str = "", length: int = 16, payload_only: bool = False) -> str:
    """
    Generate a readable hex dump of binary data.
    
    Args:
        data: Binary data to dump
        prefix: Prefix for each line (default: "")
        length: Bytes per line (default: 16)
        payload_only: If False, include full packet; if True, payload only
        
    Returns:
        Multi-line hex dump string
    """
    lines = []
    for offset in range(0, len(data), length):
        chunk = data[offset:offset + length]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        line = f"{prefix}{offset:04x}  {hex_str:<{length*3}}  {ascii_str}"
        lines.append(line)
    return '\n'.join(lines) if lines else f"{prefix}(empty)"


def extract_packet_info(packet: Packet, timestamp: Optional[float] = None) -> Dict[str, Any]:
    """
    Extract structured information from a Scapy packet.
    
    Args:
        packet: Scapy packet object
        timestamp: Unix timestamp (if None, uses current time)
        
    Returns:
        Dictionary with parsed packet information
    """
    if timestamp is None:
        timestamp = datetime.now().timestamp()
    
    info = {
        'timestamp': timestamp,
        'timestamp_iso': datetime.fromtimestamp(timestamp).isoformat(),
        'summary': packet.summary(),
        'raw_bytes': bytes(packet),
        'layer_stack': get_layer_stack(packet),
        'ip_src': None,
        'ip_dst': None,
        'l4_proto': None,
        'sport': None,
        'dport': None,
        'tcp_flags': None,
        'dns_queries': [],
        'http_host': None,
        'http_path': None,
        'payload_bytes': b'',
    }
    
    # Extract IP information
    ip_layer = packet.getlayer(IP)
    if ip_layer:
        info['ip_src'] = ip_layer.src
        info['ip_dst'] = ip_layer.dst
    
    # Extract TCP information
    tcp_layer = packet.getlayer(TCP)
    if tcp_layer:
        info['l4_proto'] = 'TCP'
        info['sport'] = tcp_layer.sport
        info['dport'] = tcp_layer.dport
        info['tcp_flags'] = extract_tcp_flags(tcp_layer)
        info['payload_bytes'] = bytes(tcp_layer.payload)
        extract_http_info(tcp_layer, info)
    
    # Extract UDP information
    udp_layer = packet.getlayer(UDP)
    if udp_layer:
        info['l4_proto'] = 'UDP'
        info['sport'] = udp_layer.sport
        info['dport'] = udp_layer.dport
        info['payload_bytes'] = bytes(udp_layer.payload)
        extract_dns_info(udp_layer, info)
    
    # Extract ICMP information
    icmp_layer = packet.getlayer(ICMP)
    if icmp_layer:
        info['l4_proto'] = 'ICMP'
    
    # Handle ARP
    if packet.haslayer('ARP'):
        info['l4_proto'] = 'ARP'
    
    return info


def get_layer_stack(packet: Packet) -> str:
    """
    Return a string representation of the packet's layer stack.
    
    Example: "Ether / IP / TCP / Raw"
    """
    layers = []
    layer = packet
    while layer:
        layers.append(layer.__class__.__name__)
        layer = layer.payload
        if not layer or layer == layer.payload:
            break
    return ' / '.join(layers)


def extract_tcp_flags(tcp_layer: TCP) -> Dict[str, bool]:
    """
    Extract TCP flags from a TCP layer.
    
    Args:
        tcp_layer: Scapy TCP layer
        
    Returns:
        Dictionary mapping flag names to booleans
    """
    flags = {
        'SYN': bool(tcp_layer.flags.S),
        'ACK': bool(tcp_layer.flags.A),
        'FIN': bool(tcp_layer.flags.F),
        'RST': bool(tcp_layer.flags.R),
        'PSH': bool(tcp_layer.flags.P),
        'URG': bool(tcp_layer.flags.U),
    }
    return flags


def extract_dns_info(udp_layer: UDP, info: Dict[str, Any]) -> None:
    """
    Extract DNS query names from UDP payload.
    
    Args:
        udp_layer: Scapy UDP layer
        info: Dictionary to update with DNS information
    """
    try:
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            dns_layer = udp_layer.getlayer(DNS)
            if dns_layer and dns_layer.qd:
                for question in dns_layer.qd:
                    qname = question.qname.decode('utf-8', errors='ignore').rstrip('.')
                    info['dns_queries'].append(qname)
    except Exception as e:
        logger.debug(f"Error parsing DNS: {e}")


def extract_http_info(tcp_layer: TCP, info: Dict[str, Any]) -> None:
    """
    Extract HTTP host and path from TCP payload.
    
    Naive parsing: looks for GET/POST/HEAD in payload and extracts Host header.
    Handles both HTTPRequest layer (if parsed by Scapy) and raw payload.
    
    Args:
        tcp_layer: Scapy TCP layer
        info: Dictionary to update with HTTP information
    """
    try:
        # Try to use Scapy's HTTPRequest if available
        http_layer = tcp_layer.getlayer(HTTPRequest)
        if http_layer:
            host = getattr(http_layer, 'Host', None)
            path = getattr(http_layer, 'Path', None)
            
            # Decode bytes to string if necessary
            if isinstance(host, bytes):
                info['http_host'] = host.decode('utf-8', errors='replace')
            else:
                info['http_host'] = host
                
            if isinstance(path, bytes):
                info['http_path'] = path.decode('utf-8', errors='replace')
            else:
                info['http_path'] = path
            return
    except Exception:
        pass
    
    # Fallback: naive parsing of raw payload
    try:
        payload = bytes(tcp_layer.payload)
        if not payload:
            return
        
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Check for HTTP methods
        if not any(payload_str.startswith(m) for m in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE']):
            return
        
        # Extract request line
        first_line = payload_str.split('\r\n')[0]
        parts = first_line.split()
        if len(parts) >= 2:
            info['http_path'] = parts[1]
        
        # Extract Host header
        for line in payload_str.split('\r\n'):
            if line.lower().startswith('host:'):
                info['http_host'] = line.split(':', 1)[1].strip()
                break
    except Exception as e:
        logger.debug(f"Error parsing HTTP: {e}")


def format_packet_display(info: Dict[str, Any], include_hexdump: bool = True) -> str:
    """
    Format packet information for display.
    
    Args:
        info: Parsed packet info dictionary
        include_hexdump: Whether to include hex dump
        
    Returns:
        Formatted string for display
    """
    lines = []
    lines.append(f"Timestamp:    {info['timestamp_iso']}")
    lines.append(f"Layer Stack:  {info['layer_stack']}")
    
    if info['ip_src']:
        lines.append(f"IP Src:       {info['ip_src']}")
    if info['ip_dst']:
        lines.append(f"IP Dst:       {info['ip_dst']}")
    
    if info['l4_proto']:
        lines.append(f"L4 Proto:     {info['l4_proto']}")
    
    if info['sport'] is not None:
        lines.append(f"Src Port:     {info['sport']}")
    if info['dport'] is not None:
        lines.append(f"Dst Port:     {info['dport']}")
    
    if info['tcp_flags']:
        flags_str = ','.join([k for k, v in info['tcp_flags'].items() if v])
        if flags_str:
            lines.append(f"TCP Flags:    {flags_str}")
    
    if info['dns_queries']:
        lines.append(f"DNS Queries:  {', '.join(info['dns_queries'])}")
    
    if info['http_host']:
        lines.append(f"HTTP Host:    {info['http_host']}")
    if info['http_path']:
        lines.append(f"HTTP Path:    {info['http_path']}")
    
    if include_hexdump:
        lines.append("\nFull Packet Hex Dump:")
        lines.append(hexdump(info['raw_bytes'], prefix="  "))
    
    return '\n'.join(lines)
