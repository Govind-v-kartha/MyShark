# MyShark: How It Captures, Parses, and Displays Packets

## Three-Stage Packet Processing Model (Like Wireshark)

MyShark works in three distinct stages, just like Wireshark:

```
Stage 1: CAPTURE          Stage 2: DISSECTION         Stage 3: DISPLAY
┌──────────────┐         ┌──────────────┐          ┌──────────────┐
│ Raw Binary   │         │ Parse Bytes  │          │ Human-Read   │
│ Data from    │  ───→   │ Into Fields  │  ───→    │ Protocol     │
│ PCAP File    │         │ (Dissectors) │          │ Tree         │
└──────────────┘         └──────────────┘          └──────────────┘
```

---

# STAGE 1: CAPTURE - Reading Raw Binary Data

## How MyShark Gets the Packet Data

MyShark doesn't capture live traffic (like Wireshark does with libpcap/Npcap). Instead, it **reads pre-captured PCAP files**.

### The Process

```python
# FILE: myshark/pcap_store.py

def load_pcap(filepath: str) -> List[Any]:
    """
    Load PCAP file and return list of packet objects
    
    This is our "CAPTURE" stage - we're reading the raw packet data
    """
    from scapy.all import rdpcap
    
    # Scapy's rdpcap() reads the PCAP file format
    # PCAP format has a header describing how packets are stored
    # Then each packet with: timestamp, length, and raw bytes
    
    packets = rdpcap(filepath)  # Returns list of Scapy Packet objects
    return packets
```

### What's Inside a Scapy Packet Object?

When Scapy reads a PCAP file, it creates a **Packet object** containing:

```python
class ScapyPacket:
    """Raw packet data structure from Scapy"""
    
    # Raw bytes - this is the actual 1s and 0s from the network
    raw_bytes = b'\x9c\x2d\xcd\x3f\x0e\xc0\x3c\xfa\x30\x03\x12\x12\x08\x00...'
    
    # Metadata
    time = 1234567890.123  # When packet was captured
    
    # Scapy's internal layer structure
    # Scapy already parsed the layers, storing them as linked objects
    layers = [
        Ether(dst='9c:2d:cd:3f:0e:c0', src='3c:fa:30:03:12:12', type=2048),
        IP(dst='192.168.21.41', src='192.168.11.1', proto=17, ...),
        UDP(sport=40269, dport=57033, len=81, chksum=0xfcb8),
        Raw(load=b'\x17\xfe\xfd\x00\x01...')
    ]
```

### Visual Representation: Raw Bytes vs Packet Object

**Raw bytes from PCAP file:**
```
00 00 00 00  ← Frame length (4 bytes)
9c 2d cd 3f 0e c0  ← Destination MAC
3c fa 30 03 12 12  ← Source MAC
08 00           ← Type = IPv4 (0x0800)
45 00           ← IP Version + Header Length
00 65           ← Total Length
88 23           ← Identification
40 00           ← Flags + Fragment Offset
fe 11           ← TTL + Protocol (17 = UDP)
52 e9           ← Checksum
c0 a8 0b 01     ← Source IP (192.168.11.1)
c0 a8 15 29     ← Dest IP (192.168.21.41)
9d 4d           ← Source Port (40269)
de c9           ← Dest Port (57033)
00 51           ← Length
fc b8           ← Checksum
...rest of data...
```

**After Scapy parses it:**
```
Packet Object:
├─ Ethernet Layer
│  ├─ dst: 9c:2d:cd:3f:0e:c0
│  ├─ src: 3c:fa:30:03:12:12
│  └─ type: 2048 (IPv4)
├─ IP Layer
│  ├─ dst: 192.168.21.41
│  ├─ src: 192.168.11.1
│  ├─ proto: 17 (UDP)
│  └─ ttl: 254
├─ UDP Layer
│  ├─ sport: 40269
│  ├─ dport: 57033
│  └─ chksum: 0xfcb8
└─ Raw Payload
   └─ data: 17 fe fd 00 01...
```

### Key Insight: Scapy Does Initial Parsing

**Important:** Scapy has **already parsed the layers** in Stage 1! So MyShark's job in Stage 1 is simple:

```python
# Stage 1: CAPTURE
packets = rdpcap("capture.pcapng")  # Scapy handles PCAP parsing
# Result: List of Packet objects with layers already identified
```

---

# STAGE 2: DISSECTION - Parsing Bytes Into Structured Data

## How MyShark Extracts Packet Details

Now that we have Packet objects with layers, we need to **extract the specific fields** from each layer. This is the "Dissection" stage.

### The Dissector Chain Pattern

Just like Wireshark has dissectors that hand off data, MyShark walks through layers:

```python
# FILE: myshark/parser.py

def extract_packet_info(packet: Any) -> ParsedPacket:
    """
    Main dissection function - extracts all packet details
    
    This implements the "Dissector Chain" pattern:
    Raw Packet → Layer Extractors → Structured Data
    """
    
    parsed = ParsedPacket()
    
    # 1. Layer Stack (highest priority - needed for rest)
    parsed.layers = _extract_layer_names(packet)  # Get ["Ether", "IP", "TCP"]
    parsed.link_type = parsed.layers[0] if parsed.layers else None
    
    # 2. Link Layer (Ethernet/Physical)
    parsed.src_mac, parsed.dst_mac = _extract_mac_addresses(packet)
    
    # 3. Network Layer (IP)
    parsed.src_ip, parsed.dst_ip = _extract_ips(packet)
    
    # 4. Transport Layer (TCP/UDP/ICMP)
    parsed.l4_proto = _extract_l4_proto(packet)          # "TCP" or "UDP"
    parsed.sport, parsed.dport = _extract_ports(packet)  # Port numbers
    parsed.tcp_flags = _extract_tcp_flags(packet)        # SYN, ACK, FIN
    
    # 5. Application Layer (DNS, HTTP)
    parsed.dns_queries = _extract_dns_queries(packet)
    parsed.http_host, parsed.http_path = _extract_http_info(packet)
    
    # 6. Raw bytes for hex dump
    parsed.raw_bytes = bytes(packet)
    parsed.payload_bytes = _extract_payload(packet)
    
    return parsed
```

### Stage 2 Deep Dive: Each Dissector

#### Dissector 1: Layer Names (Get Protocol Stack)

```python
def _extract_layer_names(packet: Any) -> List[str]:
    """
    Walk through the packet layers (like Wireshark's hand-off chain)
    
    Hand-off Chain:
    Ethernet → IP → TCP → Raw
    
    Each packet is a LINKED LIST of layers:
    packet → packet.payload → packet.payload.payload → ...
    """
    layers = []
    current = packet
    
    # Walk the linked list
    while current:
        if hasattr(current, "name"):
            # Each Scapy layer has a .name property
            layers.append(current.name)
            # Examples: "Ether", "IP", "TCP", "DNS", "Raw"
        
        # Move to next layer (Scapy's structure)
        current = current.payload if hasattr(current, "payload") else None
    
    return layers if layers else ["Unknown"]
```

**Example Output:**
```python
packet = rdpcap("file.pcap")[0]
layers = _extract_layer_names(packet)
print(layers)
# Output: ['Ether', 'IP', 'UDP', 'Raw']
```

#### Dissector 2: MAC Addresses (Link Layer - Bytes 0-14)

```python
def _extract_mac_addresses(packet: Any) -> Tuple[str, str]:
    """
    Extract MAC addresses from Ethernet layer
    
    ETHERNET FRAME STRUCTURE (first 14 bytes):
    Bytes 0-5:   Destination MAC (6 bytes)
    Bytes 6-11:  Source MAC (6 bytes)
    Bytes 12-13: Type/Length (2 bytes) - tells us what's next
    Bytes 14+:   Payload (IP, ARP, etc.)
    
    In raw hex:
    9c 2d cd 3f 0e c0 | 3c fa 30 03 12 12 | 08 00 | [IP PACKET HERE]
    └─ Dest MAC ─┘    └─ Source MAC ─┘   └Type┘
    """
    
    try:
        from scapy.layers.l2 import Ether
        
        # Check if packet has Ethernet layer
        if packet.haslayer(Ether):
            eth = packet[Ether]  # Extract the Ethernet layer object
            
            # Ether object has .src and .dst already parsed
            return eth.src, eth.dst
            # Returns: ('3c:fa:30:03:12:12', '9c:2d:cd:3f:0e:c0')
    
    except Exception:
        pass
    
    return None, None
```

**Example:**
```python
packet = rdpcap("file.pcap")[0]
src_mac, dst_mac = _extract_mac_addresses(packet)
print(f"Source: {src_mac}")    # 3c:fa:30:03:12:12
print(f"Destination: {dst_mac}")  # 9c:2d:cd:3f:0e:c0
```

#### Dissector 3: IP Addresses (Network Layer - Bytes 12-16 for Src, 16-20 for Dst)

```python
def _extract_ips(packet: Any) -> Tuple[str, str]:
    """
    Extract IP addresses from IP layer
    
    IPv4 HEADER STRUCTURE (20 bytes minimum):
    Bytes 0-3:    Version (4 bits) + Header Length (4 bits) + Service Type (8 bits)
    Bytes 4-5:    Total Length (2 bytes)
    ...
    Bytes 12-15:  Source IP Address (4 bytes = 32 bits)
    Bytes 16-19:  Destination IP Address (4 bytes = 32 bits)
    Bytes 20+:    Payload (TCP, UDP, ICMP, etc.)
    
    In raw hex for IP:
    45 00 00 65 88 23 40 00 fe 11 52 e9 | c0 a8 0b 01 | c0 a8 15 29 | [TCP/UDP HERE]
                                         └ Source IP ┘ └ Dest IP ┘
    
    Breaking down 192.168.11.1:
    c0 = 192
    a8 = 168
    0b = 11
    01 = 1
    """
    
    try:
        from scapy.layers.inet import IP
        
        # Check if IPv4 layer exists
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            
            # IP layer has .src and .dst already parsed to dotted notation
            return ip_layer.src, ip_layer.dst
            # Returns: ('192.168.11.1', '192.168.21.41')
    
    except Exception:
        pass
    
    # Try IPv6 if no IPv4
    try:
        from scapy.layers.inet6 import IPv6
        
        if packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            return ipv6_layer.src, ipv6_layer.dst
    
    except Exception:
        pass
    
    return None, None
```

#### Dissector 4: Protocol Detection (TCP vs UDP vs ICMP)

```python
def _extract_l4_proto(packet: Any) -> Optional[str]:
    """
    Detect Layer 4 protocol (Transport Layer)
    
    This works by checking which layer exists in the packet.
    
    How the detection works:
    1. Check if TCP layer exists in packet
    2. If not, check UDP
    3. If not, check ICMP
    4. If none, return None
    
    Protocol Detection Byte (in IP header):
    Byte 9 of IP header contains protocol number:
    1 = ICMP
    6 = TCP
    17 = UDP
    
    In our raw example (from before):
    45 00 00 65 88 23 40 00 fe 11 52 e9 c0 a8 0b 01 c0 a8 15 29
                              ^^^^
                              Protocol = 0x11 = 17 (UDP)
    
    But Scapy already parsed this, so we just check:
    """
    
    try:
        from scapy.layers.inet import TCP, UDP, ICMP
        
        # Scapy provides convenience method: haslayer()
        if packet.haslayer(TCP):
            return "TCP"      # Protocol 6
        
        elif packet.haslayer(UDP):
            return "UDP"      # Protocol 17
        
        elif packet.haslayer(ICMP):
            return "ICMP"     # Protocol 1
    
    except Exception:
        pass
    
    return None
```

#### Dissector 5: Port Numbers (TCP/UDP Header)

```python
def _extract_ports(packet: Any) -> Tuple[int, int]:
    """
    Extract port numbers from TCP or UDP header
    
    TCP HEADER STRUCTURE (first 20 bytes of TCP segment):
    Bytes 0-1:   Source Port (2 bytes = 16 bits, range 0-65535)
    Bytes 2-3:   Destination Port (2 bytes = 16 bits)
    Bytes 4-7:   Sequence Number (4 bytes)
    ...
    
    In raw hex:
    9d 4d de c9 88 23 40 00 fe 11 52 e9 ...
    └Sport─┘└Dport─┘
    
    Parsing 9d 4d (source port):
    9d = 157 (high byte)
    4d = 77 (low byte)
    Combined (big-endian): 157 * 256 + 77 = 40269
    
    Parsing de c9 (dest port):
    de = 222 (high byte)
    c9 = 201 (low byte)
    Combined: 222 * 256 + 201 = 57033
    """
    
    try:
        from scapy.layers.inet import TCP, UDP
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            # Scapy already converted to integers
            return tcp_layer.sport, tcp_layer.dport
            # Returns: (40269, 57033)
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            
            return udp_layer.sport, udp_layer.dport
            # Returns: (40269, 57033)
    
    except Exception:
        pass
    
    return None, None
```

#### Dissector 6: TCP Flags (Individual Bits - Bit Masking)

```python
def _extract_tcp_flags(packet: Any) -> List[str]:
    """
    Extract TCP control flags using BIT MASKING
    
    TCP FLAGS FIELD (byte 13 of TCP header):
    7 6 5 4 3 2 1 0  (bit positions)
    U A P R S F | 0 0  (flag names)
    
    Each flag is ONE BIT:
    - U (Urgent): bit 5 = 0x20
    - A (Acknowledgement): bit 4 = 0x10
    - P (Push): bit 3 = 0x08
    - R (Reset): bit 2 = 0x04
    - S (Sync): bit 1 = 0x02
    - F (Finish): bit 0 = 0x01
    
    Example: SYN+ACK packet
    Raw flags byte: 0x12
    Binary: 0001 0010
            ↑    ↑
            S    A    (bits 1 and 4 are set)
    
    To check if SYN flag is set:
    (0x12 & 0x02) != 0  →  (18 & 2) != 0  →  True (SYN is set)
    
    To check if FIN flag is set:
    (0x12 & 0x01) != 0  →  (18 & 1) != 0  →  False (FIN is not set)
    """
    
    flags = []
    
    try:
        from scapy.layers.inet import TCP
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            # Scapy provides easy flag access
            # We could do bit masking, but Scapy handles it for us
            
            if tcp_layer.flags.F:  # Check FIN bit
                flags.append("FIN")
            
            if tcp_layer.flags.S:  # Check SYN bit
                flags.append("SYN")
            
            if tcp_layer.flags.R:  # Check RST bit
                flags.append("RST")
            
            if tcp_layer.flags.A:  # Check ACK bit
                flags.append("ACK")
            
            if tcp_layer.flags.P:  # Check PSH bit
                flags.append("PSH")
            
            if tcp_layer.flags.U:  # Check URG bit
                flags.append("URG")
    
    except Exception:
        pass
    
    return flags
    # Returns: ["SYN", "ACK"] for TCP handshake response
```

**Manual Bit Masking Example (if Scapy didn't help):**
```python
def extract_flags_manual(flags_byte: int) -> List[str]:
    """
    Extract flags by manually checking each bit
    """
    flags = []
    
    if flags_byte & 0x01:  # Check bit 0 (FIN)
        flags.append("FIN")
    
    if flags_byte & 0x02:  # Check bit 1 (SYN)
        flags.append("SYN")
    
    if flags_byte & 0x04:  # Check bit 2 (RST)
        flags.append("RST")
    
    if flags_byte & 0x08:  # Check bit 3 (PSH)
        flags.append("PSH")
    
    if flags_byte & 0x10:  # Check bit 4 (ACK)
        flags.append("ACK")
    
    if flags_byte & 0x20:  # Check bit 5 (URG)
        flags.append("URG")
    
    return flags

# Usage:
flags_byte = 0x12  # Binary: 0001 0010 (SYN + ACK)
result = extract_flags_manual(flags_byte)
print(result)  # ['SYN', 'ACK']
```

#### Dissector 7: DNS Queries (Application Layer)

```python
def _extract_dns_queries(packet: Any) -> List[str]:
    """
    Extract DNS query names (Application Layer)
    
    DNS works like this:
    1. Client sends UDP packet to port 53 (DNS server)
    2. DNS payload contains question section
    3. Each question has: QNAME (domain name), QTYPE, QCLASS
    
    Raw DNS query for "google.com":
    00 01    ← DNS Transaction ID
    01 00    ← Flags
    00 01    ← Questions count = 1
    00 00    ← Answer RRs count
    00 00    ← Authority RRs count
    00 00    ← Additional RRs count
    [QUESTION SECTION]
    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  ← Domain name in DNS format
       g  o  o  g  l  e     c  o  m
    00 01    ← Query Type (A record)
    00 01    ← Query Class (IN - Internet)
    
    DNS name format: length-prefixed labels
    06 = next 6 bytes are the label
    67 6f 6f 67 6c 65 = "google"
    03 = next 3 bytes
    63 6f 6d = "com"
    00 = end of name
    """
    
    queries = []
    
    try:
        from scapy.layers.dns import DNS, DNSQR
        
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
            # DNS layer has .qdcount (question count)
            # and .questions list already parsed
            
            if dns_layer.questions:
                for question in dns_layer.questions:
                    # qname is already converted to string format
                    query_name = question.qname.decode('utf-8')
                    queries.append(query_name)
                    # Returns: "google.com" (or "google.com.")
    
    except Exception:
        pass
    
    return queries
    # Returns: ["google.com", "facebook.com"]
```

---

# STAGE 3: DISPLAY - Showing Results to User

## How MyShark Presents the Data

After dissection, MyShark displays results in three ways:

### Display Method 1: CLI Table Format

```python
# FILE: myshark/cli.py

def display_packets_table(packets: List[ParsedPacket]):
    """
    Display packets as formatted table (like Wireshark's main pane)
    """
    print("=" * 100)
    print(f"{'#':<5} {'Time':<12} {'Src':<20} {'Dst':<20} {'Proto':<8} {'Summary':<30}")
    print("=" * 100)
    
    for i, packet in enumerate(packets):
        # Format each row:
        # ID | Timestamp | Source | Destination | Protocol | Summary
        
        src = f"{packet.src_ip}:{packet.sport}" if packet.src_ip else "N/A"
        dst = f"{packet.dst_ip}:{packet.dport}" if packet.dst_ip else "N/A"
        proto = packet.l4_proto or "?"
        
        print(f"{i:<5} {packet.timestamp_iso[11:19]:<12} {src:<20} {dst:<20} {proto:<8} {packet.summary:<30}")
    
    print("=" * 100)
```

**Output:**
```
====================================================================================================
#     Time             Src                   Dst                   Proto   Summary
====================================================================================================
0     21:31:41        192.168.11.1:40269    192.168.21.41:57033   UDP     2a10:50c0::ad1:ff -> ...
1     21:31:41        192.168.11.2:40270    192.168.21.42:57034   TCP     HTTP GET /index.html
2     21:31:42        10.0.0.1:646          224.0.0.2:646         UDP     DNS query: google.com
====================================================================================================
```

### Display Method 2: Detailed Packet View (Like Wireshark Protocol Tree)

```python
def display_packet_details(parsed: ParsedPacket):
    """
    Display packet details in hierarchical format (like Wireshark's middle pane)
    
    Wireshark Protocol Tree:
    ├─ Frame 42: 115 bytes on wire (920 bits), 115 bytes captured
    ├─ Ethernet II
    │  ├─ Destination MAC: 9c:2d:cd:3f:0e:c0
    │  ├─ Source MAC: 3c:fa:30:03:12:12
    │  └─ Type: IPv4 (0x0800)
    ├─ Internet Protocol Version 4
    │  ├─ Version: 4
    │  ├─ Header Length: 20 bytes
    │  ├─ Source IP: 192.168.11.1
    │  ├─ Destination IP: 192.168.21.41
    │  └─ Protocol: UDP (17)
    ├─ User Datagram Protocol
    │  ├─ Source Port: 40269
    │  ├─ Destination Port: 57033
    │  └─ Length: 81
    └─ Data (41 bytes)
    """
    
    print("=" * 80)
    print("PACKET DETAILS")
    print("=" * 80)
    
    # Frame/Timestamp
    print(f"\n[Frame]")
    print(f"  Timestamp: {parsed.timestamp_iso}")
    print(f"  Length: {len(parsed.raw_bytes)} bytes")
    print(f"  Layers: {' / '.join(parsed.layers)}")
    
    # Link Layer
    print(f"\n[{parsed.link_type or 'Link Layer'}]")
    if parsed.src_mac and parsed.dst_mac:
        print(f"  Source MAC: {parsed.src_mac}")
        print(f"  Dest MAC: {parsed.dst_mac}")
    
    # Network Layer
    if parsed.src_ip or parsed.dst_ip:
        print(f"\n[Network Layer - IP]")
        if parsed.src_ip:
            print(f"  Source IP: {parsed.src_ip}")
        if parsed.dst_ip:
            print(f"  Dest IP: {parsed.dst_ip}")
    
    # Transport Layer
    if parsed.l4_proto:
        print(f"\n[Transport Layer - {parsed.l4_proto}]")
        if parsed.sport:
            print(f"  Source Port: {parsed.sport}")
        if parsed.dport:
            print(f"  Dest Port: {parsed.dport}")
        
        if parsed.tcp_flags:
            print(f"  TCP Flags: {', '.join(parsed.tcp_flags)}")
    
    # Application Layer
    if parsed.dns_queries:
        print(f"\n[Application Layer - DNS]")
        for query in parsed.dns_queries:
            print(f"  Query: {query}")
    
    if parsed.http_host:
        print(f"\n[Application Layer - HTTP]")
        print(f"  Host: {parsed.http_host}")
        print(f"  Path: {parsed.http_path}")
    
    print("\n" + "=" * 80)
```

### Display Method 3: Hex Dump (Like Wireshark's Bottom Pane)

```python
def hexdump(data: bytes, length: int = 16) -> str:
    """
    Display raw bytes in hex format (like Wireshark hex viewer)
    
    Wireshark Hex Viewer:
    00000000  ff ff ff ff ff ff 00 04 00 83 76 2c 80 35 00 01   ..........v,.5..
    00000010  08 00 06 04 00 03 00 04 00 83 76 2c 00 00 00 00   ..........v,....
    00000020  00 04 00 83 76 2c 00 00 00 00 00 00 00 00 00 00   ....v,..........
    00000030  00 00 00 00 00 00 00 00 00 00 00 00               ............
    
    Format:
    [Offset] [Hex Bytes (16 per line)] [ASCII representation]
    """
    
    result = []
    
    for i in range(0, len(data), length):
        # Offset (hex)
        offset = f"{i:08x}"
        
        # Get chunk of bytes
        chunk = data[i:i + length]
        
        # Convert to hex
        hex_str = ' '.join(f"{byte:02x}" for byte in chunk)
        
        # Pad hex string if last chunk is short
        hex_str = hex_str.ljust(length * 3)
        
        # Convert to ASCII (printable chars only)
        ascii_str = ''
        for byte in chunk:
            if 32 <= byte < 127:  # Printable ASCII range
                ascii_str += chr(byte)
            else:
                ascii_str += '.'
        
        # Combine all parts
        line = f"{offset}  {hex_str}   {ascii_str}"
        result.append(line)
    
    return '\n'.join(result)
```

**Output:**
```
00000000  9c 2d cd 3f 0e c0 3c fa 30 03 12 12 08 00 45 00   .-.?..<.0.....E.
00000010  00 65 88 23 40 00 fe 11 52 e9 c0 a8 0b 01 c0 a8   .e.#@...R.......
00000020  15 29 9d 4d de c9 00 51 fc b8 17 fe fd 00 01 00   .).M...Q........
00000030  00 00 00 00 29 00 3c 00 01 00 00 00 00 00 29 e7   ....).<.......).
00000040  27 9f 70 1e c8 ca 6e 30 32 d0 f8 0f 81 45 2b 9c   '.p...n02....E+.
00000050  0f 81 ec 34 bd 88 b2 d0 c7 06 84 00 9b 5c 5f db   ...4.........\_.
00000060  d6 5e 4c bc db ce dc c8 76 e4 e3 60 9a 5c 55 7b   .^L.....v..`.\U{
00000070  a8 80 18                                          ...
```

---

# Complete Code Flow Example

## From Raw Bytes to Display

```python
# Step 1: CAPTURE
from scapy.all import rdpcap
packets = rdpcap("network_capture.pcap")
packet = packets[0]

# Raw packet object:
# packet.raw = b'\x9c\x2d\xcd\x3f...' (1,000+ bytes of binary data)
# packet.layers = [Ether(), IP(), TCP(), Raw()]

print("STAGE 1 - CAPTURE:")
print(f"Raw bytes: {packet[0:20]}")  # First 20 bytes
# Output: b'\x9c\x2d\xcd\x3f\x0e\xc0\x3c\xfa\x30\x03\x12\x12...'


# Step 2: DISSECTION
from myshark.parser import extract_packet_info
parsed = extract_packet_info(packet)

print("\nSTAGE 2 - DISSECTION:")
print(f"Source IP: {parsed.src_ip}")        # 192.168.11.1
print(f"Dest IP: {parsed.dst_ip}")          # 192.168.21.41
print(f"Source Port: {parsed.sport}")       # 40269
print(f"Dest Port: {parsed.dport}")         # 57033
print(f"Protocol: {parsed.l4_proto}")       # UDP
print(f"Layers: {parsed.layers}")           # ['Ether', 'IP', 'UDP', 'Raw']


# Step 3: DISPLAY
print("\nSTAGE 3 - DISPLAY:")

# Display as table
print(f"\n{'Time':<12} {'Src':<20} {'Dst':<20} {'Proto':<6}")
print(parsed.timestamp_iso[11:19], f"{parsed.src_ip}:{parsed.sport}", 
      f"{parsed.dst_ip}:{parsed.dport}", parsed.l4_proto)

# Display details
print(f"\nDetailed View:")
print(f"  Frame Length: {len(parsed.raw_bytes)} bytes")
print(f"  Timestamp: {parsed.timestamp_iso}")
print(f"  Source: {parsed.src_mac} → {parsed.src_ip}:{parsed.sport}")
print(f"  Dest: {parsed.dst_mac} → {parsed.dst_ip}:{parsed.dport}")

# Display hex dump
from myshark.parser import hexdump
print(f"\nHex Dump (first 64 bytes):")
print(hexdump(parsed.raw_bytes[:64]))
```

**Output:**
```
STAGE 1 - CAPTURE:
Raw bytes: b'\x9c\x2d\xcd\x3f\x0e\xc0\x3c\xfa\x30\x03\x12\x12\x08\x00\x45\x00\x00\x65\x88\x23'

STAGE 2 - DISSECTION:
Source IP: 192.168.11.1
Dest IP: 192.168.21.41
Source Port: 40269
Dest Port: 57033
Protocol: UDP
Layers: ['Ether', 'IP', 'UDP', 'Raw']

STAGE 3 - DISPLAY:
Time        Src                  Dst                  Proto 
13:04:16    192.168.11.1:40269   192.168.21.41:57033  UDP   

Detailed View:
  Frame Length: 115 bytes
  Timestamp: 2009-05-04T13:04:16.122475
  Source: 3c:fa:30:03:12:12 → 192.168.11.1:40269
  Dest: 9c:2d:cd:3f:0e:c0 → 192.168.21.41:57033

Hex Dump (first 64 bytes):
00000000  9c 2d cd 3f 0e c0 3c fa 30 03 12 12 08 00 45 00   .-.?..<.0.....E.
00000010  00 65 88 23 40 00 fe 11 52 e9 c0 a8 0b 01 c0 a8   .e.#@...R.......
00000020  15 29 9d 4d de c9 00 51 fc b8 17 fe fd 00 01 00   .).M...Q........
00000030  00 00 00 00 29 00 3c 00 01 00 00 00 00 00 29 e7   ....).<.......).
```

---

# Comparison: MyShark vs Wireshark

| Feature | Wireshark | MyShark |
|---------|-----------|---------|
| **Capture Stage** | libpcap/Npcap (live capture) | Scapy reads PCAP files |
| **Dissection** | C-based dissectors (protocol-specific) | Python dissector functions |
| **Hand-off Chain** | Automatic (framework) | Manual layer walking |
| **Bit Masking** | Hardware-optimized C | Python boolean operations |
| **Display** | GUI (3 panes) | CLI/Web/Hex |
| **Speed** | Fast (C) | Slower (Python) |
| **Extensibility** | Complex (C plugins) | Easy (Python functions) |

---

This is exactly how MyShark implements the Wireshark model!

