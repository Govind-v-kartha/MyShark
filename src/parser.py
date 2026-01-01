"""
Packet parsing and field extraction utilities for network traffic analysis.
Supports multiple protocol layers including Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, and 802.11 (WiFi).
"""

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Deauth, Dot11Disas, Dot11Elt
from typing import Dict, Optional, List, Any
import logging

logger = logging.getLogger(__name__)


class PacketParser:
    
    def __init__(self, packet: Packet):
        """
        Initialize parser with a Scapy packet object.
        
        Args:
            packet: Scapy Packet object loaded from rdpcap
        """
        self.packet = packet
        self.parsed_data: Dict[str, Any] = {}
        
    def parse(self) -> Dict[str, Any]:
        """
        Parse the packet and extract all relevant fields.
        
        
        Returns:
            Dictionary containing all extracted packet information
        """
        self.parsed_data = {
            'timestamp': self._extract_timestamp(),
            'packet_length': len(self.packet),
            'protocol_stack': self._extract_protocol_stack(),
            'dot11': self._parse_dot11(),
            'ethernet': self._parse_ethernet(),
            'arp': self._parse_arp(),
            'ip': self._parse_ip(),
            'ipv6': self._parse_ipv6(),
            'tcp': self._parse_tcp(),
            'udp': self._parse_udp(),
            'icmp': self._parse_icmp(),
            'dns': self._parse_dns(),
            'http': self._parse_http(),
            'raw_payload': self._extract_raw_payload(),
            'summary': self.packet.summary()
        }
        
        # Remove None values for cleaner output
        self.parsed_data = {k: v for k, v in self.parsed_data.items() if v is not None}
        
        return self.parsed_data
    
    def _extract_timestamp(self) -> Optional[float]:
        return getattr(self.packet, 'time', None)
    
    def _extract_protocol_stack(self) -> List[str]:
        return [layer.__name__ if hasattr(layer, '__name__') else str(layer) for layer in self.packet.layers()]
    
    def _parse_dot11(self) -> Optional[Dict[str, Any]]:
        """Parse 802.11 (WiFi) layer fields."""
        if not self.packet.haslayer(Dot11):
            return None
        
        dot11 = self.packet[Dot11]
        parsed_dot11 = {
            'type': dot11.type,
            'subtype': dot11.subtype,
            'type_name': self._get_dot11_type_name(dot11.type, dot11.subtype),
            'addr1': dot11.addr1,  # Destination/Receiver
            'addr2': dot11.addr2,  # Source/Transmitter
            'addr3': dot11.addr3 if hasattr(dot11, 'addr3') else None,  # BSSID or filtering
            'addr4': dot11.addr4 if hasattr(dot11, 'addr4') else None,  # Only in WDS
            'SC': dot11.SC,  # Sequence Control
        }
        
        # Parse specific 802.11 frame types
        if self.packet.haslayer(Dot11Beacon):
            beacon = self.packet[Dot11Beacon]
            parsed_dot11['beacon'] = {
                'timestamp': beacon.timestamp,
                'beacon_interval': beacon.beacon_interval,
                'cap': beacon.cap
            }
            # Extract SSID and other information elements
            parsed_dot11['info_elements'] = self._parse_dot11_info_elements()
        
        elif self.packet.haslayer(Dot11ProbeReq):
            parsed_dot11['probe_request'] = True
            parsed_dot11['info_elements'] = self._parse_dot11_info_elements()
        
        elif self.packet.haslayer(Dot11ProbeResp):
            probe_resp = self.packet[Dot11ProbeResp]
            parsed_dot11['probe_response'] = {
                'timestamp': probe_resp.timestamp,
                'beacon_interval': probe_resp.beacon_interval,
                'cap': probe_resp.cap
            }
            parsed_dot11['info_elements'] = self._parse_dot11_info_elements()
        
        elif self.packet.haslayer(Dot11AssoReq):
            asso_req = self.packet[Dot11AssoReq]
            parsed_dot11['association_request'] = {
                'cap': asso_req.cap,
                'listen_interval': asso_req.listen_interval
            }
            parsed_dot11['info_elements'] = self._parse_dot11_info_elements()
        
        elif self.packet.haslayer(Dot11AssoResp):
            asso_resp = self.packet[Dot11AssoResp]
            parsed_dot11['association_response'] = {
                'cap': asso_resp.cap,
                'status': asso_resp.status,
                'AID': asso_resp.AID
            }
        
        elif self.packet.haslayer(Dot11Auth):
            auth = self.packet[Dot11Auth]
            parsed_dot11['authentication'] = {
                'algo': auth.algo,
                'seqnum': auth.seqnum,
                'status': auth.status
            }
        
        elif self.packet.haslayer(Dot11Deauth):
            deauth = self.packet[Dot11Deauth]
            parsed_dot11['deauthentication'] = {
                'reason': deauth.reason
            }
        
        elif self.packet.haslayer(Dot11Disas):
            disas = self.packet[Dot11Disas]
            parsed_dot11['disassociation'] = {
                'reason': disas.reason
            }
        
        return parsed_dot11
    
    def _parse_dot11_info_elements(self) -> Dict[str, Any]:
        """Parse 802.11 information elements (IEs)."""
        info_elements = {}
        
        if self.packet.haslayer(Dot11Elt):
            elt = self.packet[Dot11Elt]
            while elt:
                try:
                    # ID 0 = SSID
                    if elt.ID == 0:
                        try:
                            info_elements['ssid'] = elt.info.decode('utf-8', errors='replace')
                        except Exception:
                            info_elements['ssid'] = elt.info.hex()
                    # ID 1 = Supported Rates
                    elif elt.ID == 1:
                        try:
                            info_elements['supported_rates'] = list(elt.info)
                        except Exception:
                            pass
                    # ID 3 = DS Parameter Set (Channel)
                    elif elt.ID == 3:
                        try:
                            info_elements['channel'] = int(elt.info[0]) if elt.info else None
                        except Exception:
                            pass
                    # ID 48 = RSN Information (WPA2)
                    elif elt.ID == 48:
                        info_elements['rsn'] = True
                    # ID 221 = Vendor Specific (often WPA)
                    elif elt.ID == 221:
                        try:
                            if b'\x00\x50\xf2\x01\x01\x00' in elt.info:
                                info_elements['wpa'] = True
                        except Exception:
                            pass
                    
                    elt = elt.payload.getlayer(Dot11Elt)
                except Exception:
                    break
        
        return info_elements
    
    def _get_dot11_type_name(self, frame_type: int, subtype: int) -> str:
        """Get human-readable 802.11 frame type name."""
        # Management frames (type 0)
        if frame_type == 0:
            management_subtypes = {
                0: 'Association Request',
                1: 'Association Response',
                2: 'Reassociation Request',
                3: 'Reassociation Response',
                4: 'Probe Request',
                5: 'Probe Response',
                8: 'Beacon',
                9: 'ATIM',
                10: 'Disassociation',
                11: 'Authentication',
                12: 'Deauthentication',
                13: 'Action'
            }
            return management_subtypes.get(subtype, f'Management (Unknown subtype {subtype})')
        
        # Control frames (type 1)
        elif frame_type == 1:
            control_subtypes = {
                10: 'PS-Poll',
                11: 'RTS',
                12: 'CTS',
                13: 'ACK',
                14: 'CF-End',
                15: 'CF-End+CF-Ack'
            }
            return control_subtypes.get(subtype, f'Control (Unknown subtype {subtype})')
        
        # Data frames (type 2)
        elif frame_type == 2:
            data_subtypes = {
                0: 'Data',
                1: 'Data+CF-Ack',
                2: 'Data+CF-Poll',
                3: 'Data+CF-Ack+CF-Poll',
                4: 'Null',
                5: 'CF-Ack',
                6: 'CF-Poll',
                7: 'CF-Ack+CF-Poll',
                8: 'QoS Data',
                12: 'QoS Null'
            }
            return data_subtypes.get(subtype, f'Data (Unknown subtype {subtype})')
        
        return f'Unknown type {frame_type} subtype {subtype}'
    
    def _parse_ethernet(self) -> Optional[Dict[str, str]]:
        """Parse Ethernet layer fields."""
        if not self.packet.haslayer(Ether):
            return None
            
        ether = self.packet[Ether]
        return {
            'src_mac': ether.src,
            'dst_mac': ether.dst,            
            'type': hex(ether.type),
            'type_name': self._get_ether_type_name(ether.type)
        }
    
    def _parse_arp(self) -> Optional[Dict[str, Any]]:
        """Parse ARP layer fields."""
        if not self.packet.haslayer(ARP):
            return None
            
        arp = self.packet[ARP]
        return {
            'operation': 'request' if arp.op == 1 else 'reply',
            'hwsrc': arp.hwsrc,
            'hwdst': arp.hwdst,
            'psrc': arp.psrc,
            'pdst': arp.pdst
        }
    
    def _parse_ip(self) -> Optional[Dict[str, Any]]:
        """Parse IPv4 layer fields."""
        if not self.packet.haslayer(IP):
            return None
            
        ip = self.packet[IP]
        return {
            'version': ip.version,
            'ihl': ip.ihl,
            'tos': ip.tos,
            'len': ip.len,
            'id': ip.id,
            'flags': self._parse_ip_flags(ip.flags),
            'frag': ip.frag,
            'ttl': ip.ttl,
            'proto': ip.proto,
            'proto_name': self._get_protocol_name(ip.proto),
            'chksum': ip.chksum,
            'src': ip.src,
            'dst': ip.dst,
            'options': ip.options if ip.options else None
        }
    
    def _parse_ipv6(self) -> Optional[Dict[str, Any]]:
        """Parse IPv6 layer fields."""
        if not self.packet.haslayer(IPv6):
            return None
            
        ipv6 = self.packet[IPv6]
        return {
            'version': ipv6.version,
            'tc': ipv6.tc,
            'fl': ipv6.fl,
            'plen': ipv6.plen,
            'nh': ipv6.nh,
            'hlim': ipv6.hlim,
            'src': ipv6.src,
            'dst': ipv6.dst
        }
    
    def _parse_tcp(self) -> Optional[Dict[str, Any]]:
        """Parse TCP layer fields."""
        if not self.packet.haslayer(TCP):
            return None
            
        tcp = self.packet[TCP]
        return {
            'sport': tcp.sport,
            'dport': tcp.dport,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'dataofs': tcp.dataofs,
            'reserved': tcp.reserved,
            'flags': self._parse_tcp_flags(tcp.flags),
            'window': tcp.window,
            'chksum': tcp.chksum,
            'urgptr': tcp.urgptr,
            'options': self._parse_tcp_options(tcp.options) if tcp.options else None,
            'payload_len': len(tcp.payload)
        }
    
    def _parse_udp(self) -> Optional[Dict[str, Any]]:
        """Parse UDP layer fields."""
        if not self.packet.haslayer(UDP):
            return None
            
        udp = self.packet[UDP]
        return {
            'sport': udp.sport,
            'dport': udp.dport,
            'len': udp.len,
            'chksum': udp.chksum,
            'payload_len': len(udp.payload)
        }
    
    def _parse_icmp(self) -> Optional[Dict[str, Any]]:
        """Parse ICMP layer fields."""
        if self.packet.haslayer(ICMP):
            icmp = self.packet[ICMP]
            return {
                'type': icmp.type,
                'type_name': self._get_icmp_type_name(icmp.type),
                'code': icmp.code,
                'chksum': icmp.chksum,
                'id': getattr(icmp, 'id', None),
                'seq': getattr(icmp, 'seq', None)
            }
        elif self.packet.haslayer(ICMPv6EchoRequest) or self.packet.haslayer(ICMPv6EchoReply):
            return {'version': 6, 'summary': 'ICMPv6 Echo Request/Reply'}
        
        return None
    
    def _parse_dns(self) -> Optional[Dict[str, Any]]:
        """Parse DNS layer fields."""
        if not self.packet.haslayer(DNS):
            return None
            
        dns = self.packet[DNS]
        parsed_dns = {
            'id': dns.id,
            'qr': dns.qr,  # 0 = query, 1 = response
            'opcode': dns.opcode,
            'aa': dns.aa,  # Authoritative Answer
            'tc': dns.tc,  # Truncated
            'rd': dns.rd,  # Recursion Desired
            'ra': dns.ra,  # Recursion Available
            'rcode': dns.rcode,
            'qdcount': dns.qdcount,
            'ancount': dns.ancount,
            'nscount': dns.nscount,
            'arcount': dns.arcount,
            'queries': [],
            'answers': []
        }
        
        # Parse DNS queries
        if dns.qd:
            for i in range(dns.qdcount):
                if dns.qd and hasattr(dns.qd, '__iter__'):
                    try:
                        qd = dns.qd if not hasattr(dns.qd, '__getitem__') else dns.qd[i] if i < len(dns.qd) else dns.qd
                        parsed_dns['queries'].append({
                            'qname': qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname),
                            'qtype': qd.qtype,
                            'qclass': qd.qclass
                        })
                    except (IndexError, AttributeError):
                        break
        
        # Parse DNS answers
        if dns.an:
            for i in range(dns.ancount):
                if dns.an and hasattr(dns.an, '__iter__'):
                    try:
                        an = dns.an if not hasattr(dns.an, '__getitem__') else dns.an[i] if i < len(dns.an) else dns.an
                        parsed_dns['answers'].append({
                            'rrname': an.rrname.decode() if isinstance(an.rrname, bytes) else str(an.rrname),
                            'type': an.type,
                            'rclass': an.rclass,
                            'ttl': an.ttl,
                            'rdata': str(an.rdata)
                        })
                    except (IndexError, AttributeError):
                        break
        
        return parsed_dns
    
    def _parse_http(self) -> Optional[Dict[str, Any]]:
        """Parse HTTP layer fields."""
        http_data = {}
        
        if self.packet.haslayer(HTTPRequest):
            http_req = self.packet[HTTPRequest]
            http_data['request'] = {
                'method': http_req.Method.decode() if hasattr(http_req, 'Method') else None,
                'host': http_req.Host.decode() if hasattr(http_req, 'Host') else None,
                'path': http_req.Path.decode() if hasattr(http_req, 'Path') else None,
                'user_agent': http_req.User_Agent.decode() if hasattr(http_req, 'User_Agent') else None
            }
        
        if self.packet.haslayer(HTTPResponse):
            http_resp = self.packet[HTTPResponse]
            http_data['response'] = {
                'status_code': http_resp.Status_Code.decode() if hasattr(http_resp, 'Status_Code') else None,
                'reason': http_resp.Reason_Phrase.decode() if hasattr(http_resp, 'Reason_Phrase') else None
            }
        
        return http_data if http_data else None
    
    def _extract_raw_payload(self) -> Optional[bytes]:
        """Extract raw payload data."""
        if self.packet.haslayer('Raw'):
            return bytes(self.packet['Raw'].load)
        return None
    
    def _parse_ip_flags(self, flags) -> Dict[str, bool]:
        """Parse IP flags."""
        return {
            'MF': bool(flags & 0x1),  # More Fragments
            'DF': bool(flags & 0x2),  # Don't Fragment
            'reserved': bool(flags & 0x4)
        }
    
    def _parse_tcp_flags(self, flags) -> Dict[str, bool]:
        """Parse TCP flags."""
        return {
            'FIN': bool(flags & 0x01),
            'SYN': bool(flags & 0x02),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'ACK': bool(flags & 0x10),
            'URG': bool(flags & 0x20),
            'ECE': bool(flags & 0x40),
            'CWR': bool(flags & 0x80)
        }
    
    def _parse_tcp_options(self, options) -> List[Dict[str, Any]]:
        """Parse TCP options."""
        parsed_options = []
        for opt in options:
            if isinstance(opt, tuple):
                parsed_options.append({
                    'kind': opt[0],
                    'value': opt[1] if len(opt) > 1 else None
                })
            else:
                parsed_options.append({'kind': opt})
        return parsed_options
    
    def _get_ether_type_name(self, etype: int) -> str:
        """Get human-readable Ethernet type name."""
        types = {
            0x0800: 'IPv4',
            0x0806: 'ARP',
            0x86DD: 'IPv6',
            0x8100: 'VLAN',
            0x88CC: 'LLDP'
        }
        return types.get(etype, 'Unknown')
    
    def _get_protocol_name(self, proto: int) -> str:
        """Get human-readable protocol name."""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            58: 'ICMPv6'
        }
        return protocols.get(proto, f'Unknown({proto})')
    
    def _get_icmp_type_name(self, icmp_type: int) -> str:
        """Get human-readable ICMP type name."""
        types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded',
            13: 'Timestamp Request',
            14: 'Timestamp Reply'
        }
        return types.get(icmp_type, f'Unknown({icmp_type})')
    
    def get_layer_info(self, layer_name: str) -> Optional[Any]:
        """
        Get information for a specific layer.
        
        Args:
            layer_name: Name of the layer (e.g., 'IP', 'TCP', 'DNS')
            
        Returns:
            Layer information if available, None otherwise
        """
        return self.parsed_data.get(layer_name.lower())
    
    def has_layer(self, layer_name: str) -> bool:
        """
        Check if packet has a specific layer.
        
        Args:
            layer_name: Name of the layer to check
            
        Returns:
            True if layer exists, False otherwise
        """
        return layer_name.lower() in self.parsed_data
    
    def get_src_dst(self) -> Dict[str, Optional[str]]:
        """
        Get source and destination addresses (IP or MAC).
        
        Returns:
            Dictionary with src and dst addresses
        """
        if 'ip' in self.parsed_data:
            return {
                'src': self.parsed_data['ip']['src'],
                'dst': self.parsed_data['ip']['dst'],
                'type': 'IPv4'
            }
        elif 'ipv6' in self.parsed_data:
            return {
                'src': self.parsed_data['ipv6']['src'],
                'dst': self.parsed_data['ipv6']['dst'],
                'type': 'IPv6'
            }
        elif 'ethernet' in self.parsed_data:
            return {
                'src': self.parsed_data['ethernet']['src_mac'],
                'dst': self.parsed_data['ethernet']['dst_mac'],
                'type': 'MAC'
            }
        return {'src': None, 'dst': None, 'type': None}
    
    def get_transport_layer(self) -> Optional[Dict[str, Any]]:
        """
        Get transport layer information (TCP or UDP).
        
        Returns:
            Transport layer data if available
        """
        if 'tcp' in self.parsed_data:
            return {'protocol': 'TCP', 'data': self.parsed_data['tcp']}
        elif 'udp' in self.parsed_data:
            return {'protocol': 'UDP', 'data': self.parsed_data['udp']}
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Get complete parsed data as dictionary.
        
        Returns:
            Dictionary containing all parsed packet information
        """
        return self.parsed_data


class PacketAnalyzer:
    """
    Analyzes collections of packets and provides statistics and filtering.
    """
    
    def __init__(self, packets: List[Packet]):
        """
        Initialize analyzer with a list of packets.
        
        Args:
            packets: List of Scapy Packet objects
        """
        self.packets = packets
        self.parsed_packets: List[PacketParser] = []
        
    def parse_all(self) -> List[Dict[str, Any]]:
        """
        Parse all packets in the collection.
        
        Returns:
            List of parsed packet dictionaries
        """
        logger.info(f"Parsing {len(self.packets)} packets...")
        self.parsed_packets = [PacketParser(pkt) for pkt in self.packets]
        parsed_data = [parser.parse() for parser in self.parsed_packets]
        logger.info(f"Successfully parsed {len(parsed_data)} packets")
        return parsed_data
    
    def filter_by_protocol(self, protocol: str) -> List[Dict[str, Any]]:
        """
        Filter packets by protocol.
        
        Args:
            protocol: Protocol name (e.g., 'TCP', 'UDP', 'DNS')
            
        Returns:
            List of packets containing the specified protocol
        """
        if not self.parsed_packets:
            self.parse_all()
        
        protocol_lower = protocol.lower()
        return [
            parser.to_dict() 
            for parser in self.parsed_packets 
            if parser.has_layer(protocol_lower)
        ]
    
    def filter_by_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Filter packets by source or destination IP.
        
        Args:
            ip_address: IP address to filter by
            
        Returns:
            List of packets involving the specified IP
        """
        if not self.parsed_packets:
            self.parse_all()
        
        filtered = []
        for parser in self.parsed_packets:
            addrs = parser.get_src_dst()
            if addrs['src'] == ip_address or addrs['dst'] == ip_address:
                filtered.append(parser.to_dict())
        
        return filtered
    
    def filter_by_port(self, port: int) -> List[Dict[str, Any]]:
        """
        Filter packets by source or destination port.
        
        Args:
            port: Port number to filter by
            
        Returns:
            List of packets involving the specified port
        """
        if not self.parsed_packets:
            self.parse_all()
        
        filtered = []
        for parser in self.parsed_packets:
            transport = parser.get_transport_layer()
            if transport:
                data = transport['data']
                if data.get('sport') == port or data.get('dport') == port:
                    filtered.append(parser.to_dict())
        
        return filtered
    
    def get_protocol_statistics(self) -> Dict[str, int]:
        """
        Get statistics on protocol distribution.
        
        Returns:
            Dictionary mapping protocol names to packet counts
        """
        if not self.parsed_packets:
            self.parse_all()
        
        stats = {}
        for parser in self.parsed_packets:
            for protocol in parser.parsed_data.get('protocol_stack', []):
                stats[protocol] = stats.get(protocol, 0) + 1
        
        return dict(sorted(stats.items(), key=lambda x: x[1], reverse=True))
    
    def get_conversation_pairs(self) -> Dict[str, int]:
        """
        Get statistics on IP conversation pairs.
        
        Returns:
            Dictionary mapping IP pairs to packet counts
        """
        if not self.parsed_packets:
            self.parse_all()
        
        conversations = {}
        for parser in self.parsed_packets:
            addrs = parser.get_src_dst()
            if addrs['src'] and addrs['dst'] and addrs['type'] in ['IPv4', 'IPv6']:
                pair = tuple(sorted([addrs['src'], addrs['dst']]))
                key = f"{pair[0]} <-> {pair[1]}"
                conversations[key] = conversations.get(key, 0) + 1
        
        return dict(sorted(conversations.items(), key=lambda x: x[1], reverse=True))