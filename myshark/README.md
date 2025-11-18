# MyShark - Lightweight Packet Capture Tool

A modular, production-quality Python tool for capturing, filtering, parsing, and inspecting network packets. Features both an interactive CLI and a minimal Flask web UI.

**Features:**
- 📦 Live packet capture with Scapy
- 🔍 Post-capture custom filtering (proto, port, IP with boolean operators)
- 🐟 BPF (Berkeley Packet Filter) support for kernel-level filtering
- 📊 Extracted packet details: timestamps, protocol stacks, TCP flags, DNS queries, HTTP headers
- 💾 Save/load packets to/from PCAP files
- 🖥️ Interactive CLI with REPL mode
- 🌐 Minimal Flask web UI with real-time packet table
- 🧪 Comprehensive unit tests
- 📝 Modular, extensible architecture

## Installation

### Prerequisites
- **Python 3.10+**
- **Linux/macOS/WSL**: Scapy requires `libpcap` development files
- **Windows**: WinPcap or Npcap must be installed (get it from [npcap.com](https://npcap.com/))

### Setup

1. Clone or download the repository:
   ```bash
   git clone <repo-url>
   cd myshark
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   # Linux/macOS:
   source venv/bin/activate
   # Windows:
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive CLI Mode

Start the interactive CLI:
```bash
python myshark.py interactive
```

Then use commands like:
```
> help
> read --pcap samples/demo.pcap
> list 20
> show 5
> filter --custom "proto:tcp and port:80"
> save capture.pcap
> quit
```

### Live Capture (Requires Admin/Root)

**Linux/macOS:**
```bash
sudo python myshark.py capture --iface eth0 --bpf "tcp port 80" --custom "proto:tcp and port:80"
```

**Windows (as Administrator):**
```bash
python myshark.py capture --iface "Ethernet" --bpf "tcp port 80"
```

To list available interfaces:
```bash
# Linux/macOS
ip link show
# or
ifconfig

# Windows
ipconfig
# or in Python:
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

### Read from PCAP File

```bash
python myshark.py read --pcap samples/demo.pcap
python myshark.py read --pcap samples/demo.pcap --custom "proto:udp and port:53"
```

### Flask Web UI

Start the web server:
```bash
python web_ui.py --host 127.0.0.1 --port 5000
```

Then open http://127.0.0.1:5000 in your browser.

**Web UI features:**
- Real-time packet table with auto-refresh
- Click any packet for detailed view
- Hex dump display (full packet and payload)
- JSON API endpoints for integration

API endpoints:
- `GET /` — Main page
- `GET /api/recent?count=50` — Recent packets JSON
- `GET /packet/<id>` — Packet detail page
- `GET /api/packet/<id>` — Packet JSON
- `GET /api/hexdump/<id>` — Hex dump JSON
- `GET /api/stats` — Capture statistics JSON

## Custom Filter Language

Post-capture filtering supports:

### Predicates
- `proto:<tcp|udp|icmp|arp>` — Match protocol
- `port:<number>` — Match source or destination port
- `ip:<address>` — Match source or destination IP address

### Boolean Operators
- `and` — Logical AND
- `or` — Logical OR
- `not` — Logical NOT
- `( )` — Parentheses for grouping

### Examples
```
proto:tcp
proto:tcp and port:80
proto:udp or proto:icmp
not proto:arp
(proto:tcp or proto:udp) and port:53
ip:192.168.1.1 and not proto:arp
proto:tcp and (port:80 or port:443) and ip:10.0.0.0/8
```

## Architecture

### Modules

**`filters.py`** — Custom filter parser and compiler
- Tokenizer for DSL expressions
- Recursive descent parser with operator precedence
- Predicate compiler for efficient matching
- Comprehensive error reporting

**`parser.py`** — Packet parsing and extraction
- Layer-aware packet information extraction
- TCP flag parsing
- DNS query extraction (UDP port 53)
- HTTP header parsing (naive but effective)
- Hex dump generation
- Type hints throughout

**`pcap_store.py`** — In-memory circular buffer
- Thread-safe append operations
- Configurable buffer size (default 500 packets)
- PCAP save/load with Scapy
- Random access by index

**`myshark.py`** — CLI orchestration
- Interactive REPL with command parser
- One-shot capture/read modes
- Privilege detection and fallback
- Interface validation
- Human-readable output formatting

**`web_ui.py`** — Flask web application
- RESTful API design
- Real-time packet updates via polling
- Responsive HTML5/CSS3 UI
- Zero external JS dependencies

**`templates/index.html`** — Packet list view
- Auto-refreshing table
- Click-to-detail navigation
- Configurable refresh intervals

**`templates/packet.html`** — Packet detail view
- Full packet information display
- Hex dump with syntax-like highlighting
- TCP flags badge display

**`static/style.css`** — Responsive styling
- Mobile-friendly design
- Dark mode hex dump display
- Gradient header

**`tests/test_myshark.py`** — Comprehensive test suite
- Filter parser tests (operators, precedence, errors)
- Predicate matching tests
- Packet extraction tests
- Hex dump generation tests
- PCAP round-trip tests
- Integration tests

### Design Principles

1. **Modularity**: Each module has a single responsibility
2. **Testability**: Pure functions where possible; comprehensive unit tests
3. **Extensibility**: Easy to add new filter predicates or parsers
4. **Performance**: In-memory buffer with circular semantics; no database required
5. **Robustness**: Graceful error handling; logs instead of silent failures
6. **Usability**: Clear CLI output; minimal learning curve

## Testing

Run the test suite:
```bash
pytest tests/ -v
```

Run specific tests:
```bash
pytest tests/test_myshark.py::TestFilterCompiler -v
pytest tests/test_myshark.py::TestPacketParsing -v
```

## Permissions & Platform Notes

### Linux
- **Live capture requires root**: Use `sudo python myshark.py capture ...`
- **Alternative**: Grant CAP_NET_RAW capability (advanced users)
  ```bash
  sudo setcap cap_net_raw=ep /usr/bin/python3
  ```
- Tested on Ubuntu 20.04+ with Scapy 2.5+

### macOS
- **Live capture requires root**: Use `sudo python3 myshark.py capture ...`
- Requires Xcode command line tools for libpcap
- Tested on macOS 12+ with Python 3.10+

### Windows
- **Live capture requires Administrator**
- Install [Npcap](https://npcap.com/) (WinPcap successor)
- Run Command Prompt/PowerShell as Administrator
- Interface names are GUIDs; use `ipconfig /all` for friendly names

### WSL (Windows Subsystem for Linux)
- Works like Linux inside WSL
- Live capture from Windows host not possible (use Windows native instead)
- PCAP file reading works normally

## Known Limitations

1. **HTTPS/TLS**: Cannot extract HTTP headers from encrypted HTTPS traffic (by design)
2. **IPv6**: Basic support only; TCP flags and DNS work; full stack analysis not implemented
3. **Performance**: Buffer size fixed at 500 packets; heavy packet streams may overflow
4. **HTTP detection**: Naive payload scanning; fragmented HTTP may not parse correctly
5. **DNS**: Basic DNS over UDP only; DoH/DoT not supported
6. **Filter precedence**: Standard C-like precedence (NOT > AND > OR); all binary operators left-associative

## Example Workflow

1. **Start web UI in background** (Terminal 1):
   ```bash
   python web_ui.py --host 0.0.0.0 --port 5000
   ```

2. **Read demo PCAP** (Terminal 2):
   ```bash
   python myshark.py read --pcap samples/demo.pcap
   ```

3. **Open browser**: http://localhost:5000
4. **Inspect packets**: Click any row in the table
5. **See hex dump**: Scroll down on packet detail page

## Developer Notes

### Adding a New Filter Predicate

1. Create a `create_<name>_predicate()` function in `filters.py`
2. Update `create_predicate()` to handle the new key
3. Add tests to `tests/test_myshark.py`
4. Document in this README

Example:
```python
# filters.py
def create_ttl_predicate(ttl_str: str) -> Callable:
    ttl = int(ttl_str)
    return lambda p: p.get('ip_ttl') == ttl

# Update create_predicate():
elif key == 'ttl':
    return create_ttl_predicate(value)
```

### Adding a New Extraction Field

1. Add field to `extract_packet_info()` dict in `parser.py`
2. Implement extraction logic (e.g., `extract_<field>_info()`)
3. Add to tests
4. Update Flask templates to display

Example:
```python
# parser.py
def extract_geoip_info(ip_addr: str, info: Dict) -> None:
    # Use MaxMind GeoIP2 or similar
    info['geoip_country'] = lookup_country(ip_addr)

# In extract_packet_info():
if info['ip_src']:
    extract_geoip_info(info['ip_src'], info)
```

### Performance Tuning

- Increase buffer size in `PcapStore(maxlen=...)` (uses more RAM)
- Use BPF filters to reduce packet volume at kernel level
- Consider indexing packets by flow (5-tuple) for faster lookups
- Profile with `cProfile` for bottleneck identification

## Contributing

Contributions welcome! Please:
1. Add tests for any new functionality
2. Run `pytest` and ensure all tests pass
3. Follow PEP 8 style guide
4. Add docstrings to functions and classes
5. Update README with new features/changes

## License

MIT License. See LICENSE file.

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BPF Syntax](https://www.tcpdump.org/papers/sniffing-faq.html)
- [RFC 1035 - DNS Protocol](https://tools.ietf.org/html/rfc1035)
- [RFC 7230 - HTTP/1.1](https://tools.ietf.org/html/rfc7230)

---
