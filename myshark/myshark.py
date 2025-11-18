"""
CLI entrypoint and capture orchestration for MyShark.

Provides interactive and one-shot command modes.
"""

import sys
import os
import logging
import argparse
import signal
from typing import Optional
from pathlib import Path

try:
    from scapy.all import sniff, rdpcap, get_if_list
    from scapy.arch import get_windows_if_list
except ImportError:
    print("Error: scapy not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

from filters import compile_custom, FilterParseError
from parser import extract_packet_info, format_packet_display
from pcap_store import PcapStore


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


class MySharkCLI:
    """Interactive CLI for MyShark packet capture and filtering."""
    
    def __init__(self, store: Optional[PcapStore] = None):
        """
        Initialize CLI.
        
        Args:
            store: PcapStore instance (creates new one if None)
        """
        self.store = store or PcapStore(maxlen=500)
        self.is_capturing = False
        self.bpf_filter = None
        self.custom_filter = None
        self.custom_filter_func = None
    
    def start_capture(self, iface: str, bpf: Optional[str] = None, 
                     custom: Optional[str] = None, packet_count: int = 0) -> None:
        """
        Start live packet capture.
        
        Args:
            iface: Interface name (e.g., "eth0", "\\Device\\NPF_{GUID}" on Windows)
            bpf: BPF filter string (optional)
            custom: Custom filter expression (optional)
            packet_count: Max packets to capture (0 = unlimited)
        """
        # Validate interface
        if not self._is_valid_interface(iface):
            print(f"Warning: Interface '{iface}' may not exist. Available interfaces:")
            self._list_interfaces()
            return
        
        # Compile custom filter if provided
        if custom:
            try:
                self.custom_filter_func = compile_custom(custom)
                self.custom_filter = custom
                print(f"Custom filter: {custom}")
            except FilterParseError as e:
                print(f"Error parsing custom filter: {e}")
                return
        
        self.bpf_filter = bpf
        self.is_capturing = True
        
        print(f"Starting capture on {iface} (BPF: {bpf or 'none'})")
        
        try:
            def packet_callback(pkt):
                """Callback for each captured packet."""
                try:
                    parsed = extract_packet_info(pkt)
                    
                    # Apply custom filter if set
                    if self.custom_filter_func:
                        if not self.custom_filter_func(parsed):
                            return
                    
                    idx = self.store.append(parsed, raw_packet=pkt)
                    print(f"[{idx}] {parsed['timestamp_iso']} | {parsed['summary'][:80]}")
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
            
            # Attempt live capture
            try:
                sniff(
                    iface=iface,
                    filter=bpf or "",
                    prn=packet_callback,
                    store=False,
                    count=packet_count if packet_count > 0 else 0,
                    timeout=None
                )
            except PermissionError:
                print("Error: Insufficient privileges for live capture.")
                print("  Linux/macOS: Run with 'sudo'")
                print("  Windows: Run as Administrator")
                self.is_capturing = False
            except OSError as e:
                if "interface" in str(e).lower():
                    print(f"Error: Cannot sniff on interface '{iface}'")
                    self._list_interfaces()
                else:
                    print(f"Error: {e}")
                self.is_capturing = False
        except KeyboardInterrupt:
            print("\nCapture stopped.")
            self.is_capturing = False
        except Exception as e:
            print(f"Capture error: {e}")
            logger.exception("Capture exception")
            self.is_capturing = False
    
    def read_pcap(self, filename: str, custom: Optional[str] = None) -> None:
        """
        Read packets from a pcap file.
        
        Args:
            filename: Path to pcap file
            custom: Custom filter expression (optional)
        """
        if not os.path.exists(filename):
            print(f"Error: File not found: {filename}")
            return
        
        # Compile custom filter if provided
        if custom:
            try:
                self.custom_filter_func = compile_custom(custom)
                self.custom_filter = custom
                print(f"Custom filter: {custom}")
            except FilterParseError as e:
                print(f"Error parsing custom filter: {e}")
                return
        
        try:
            packets = rdpcap(filename)
            print(f"Read {len(packets)} packets from {filename}")
            
            for pkt in packets:
                try:
                    parsed = extract_packet_info(pkt)
                    
                    # Apply custom filter if set
                    if self.custom_filter_func:
                        if not self.custom_filter_func(parsed):
                            continue
                    
                    idx = self.store.append(parsed, raw_packet=pkt)
                    print(f"[{idx}] {parsed['timestamp_iso']} | {parsed['summary'][:80]}")
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
        except Exception as e:
            print(f"Error reading pcap: {e}")
    
    def list_packets(self, count: int = 10) -> None:
        """
        List recent packets.
        
        Args:
            count: Number of recent packets to show
        """
        packets = self.store.get_all()
        
        if not packets:
            print("No packets captured yet.")
            return
        
        # Show last 'count' packets
        start = max(0, len(packets) - count)
        
        print(f"\n{'Idx':<4} {'Timestamp':<26} {'Src:Port':<20} {'Dst:Port':<20} {'Proto':<6} {'Summary':<40}")
        print("-" * 120)
        
        for i in range(start, len(packets)):
            pkt = packets[i]
            ts = pkt['timestamp_iso'][:19] if 'timestamp_iso' in pkt else '?'
            proto = pkt.get('l4_proto', '?')
            
            src = f"{pkt.get('ip_src', '?')}"
            if pkt.get('sport'):
                src += f":{pkt['sport']}"
            
            dst = f"{pkt.get('ip_dst', '?')}"
            if pkt.get('dport'):
                dst += f":{pkt['dport']}"
            
            summary = pkt['summary'][:39] if 'summary' in pkt else '?'
            
            # Index relative to stored position
            actual_idx = i
            print(f"{actual_idx:<4} {ts:<26} {src:<20} {dst:<20} {proto:<6} {summary:<40}")
    
    def show_packet(self, index: int) -> None:
        """
        Show detailed information for a packet.
        
        Args:
            index: Packet index
        """
        pkt = self.store.get(index)
        if not pkt:
            print(f"Error: No packet at index {index}")
            return
        
        print(f"\n=== Packet {index} ===\n")
        print(format_packet_display(pkt, include_hexdump=True))
    
    def save_pcap(self, filename: str) -> None:
        """
        Save captured packets to pcap file.
        
        Args:
            filename: Output filename
        """
        try:
            self.store.save_to_pcap(filename)
            print(f"Saved {self.store.length()} packets to {filename}")
        except Exception as e:
            print(f"Error saving pcap: {e}")
    
    def apply_filter(self, bpf: Optional[str] = None, custom: Optional[str] = None) -> None:
        """
        Apply filters to captured packets or restart capture.
        
        Args:
            bpf: BPF filter for future capture
            custom: Custom post-filter to apply to current buffer
        """
        if custom:
            try:
                filter_func = compile_custom(custom)
                print(f"Applying custom filter: {custom}")
                
                all_packets = self.store.get_all()
                matched = sum(1 for p in all_packets if filter_func(p))
                print(f"Matched {matched} of {len(all_packets)} packets")
            except FilterParseError as e:
                print(f"Error parsing filter: {e}")
                return
        
        if bpf:
            self.bpf_filter = bpf
            print(f"BPF filter updated to: {bpf}")
            print("Re-start capture for new filter to take effect.")
    
    def _is_valid_interface(self, iface: str) -> bool:
        """Check if interface exists."""
        try:
            all_ifaces = get_if_list()
            # On Windows, also check Windows interface names
            try:
                all_ifaces += [i[0] for i in get_windows_if_list()]
            except Exception:
                pass
            return iface in all_ifaces
        except Exception:
            return False
    
    def _list_interfaces(self) -> None:
        """Print available network interfaces."""
        try:
            ifaces = get_if_list()
            print("Available interfaces:")
            for i in ifaces:
                print(f"  {i}")
        except Exception as e:
            logger.debug(f"Error listing interfaces: {e}")
    
    def interactive_mode(self) -> None:
        """Run interactive CLI REPL."""
        print("MyShark Interactive CLI")
        print("Type 'help' for commands, 'quit' to exit\n")
        
        while True:
            try:
                cmd = input("> ").strip()
                if not cmd:
                    continue
                
                self._process_command(cmd)
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit.")
            except EOFError:
                break
    
    def _process_command(self, cmd: str) -> bool:
        """
        Process a CLI command.
        
        Args:
            cmd: Command string
            
        Returns:
            True if should continue, False if quit
        """
        parts = cmd.split()
        if not parts:
            return True
        
        command = parts[0].lower()
        
        if command == 'help':
            self._print_help()
        
        elif command == 'quit' or command == 'exit':
            print("Exiting...")
            return False
        
        elif command == 'list':
            count = int(parts[1]) if len(parts) > 1 else 10
            self.list_packets(count)
        
        elif command == 'show':
            if len(parts) < 2:
                print("Usage: show <index>")
                return True
            try:
                index = int(parts[1])
                self.show_packet(index)
            except ValueError:
                print("Invalid index")
        
        elif command == 'save':
            if len(parts) < 2:
                print("Usage: save <filename.pcap>")
                return True
            self.save_pcap(parts[1])
        
        elif command == 'capture':
            self._handle_capture_command(parts[1:])
        
        elif command == 'read':
            self._handle_read_command(parts[1:])
        
        elif command == 'filter':
            self._handle_filter_command(parts[1:])
        
        else:
            print(f"Unknown command: {command}. Type 'help' for list of commands.")
        
        return True
    
    def _handle_capture_command(self, args: list[str]) -> None:
        """Handle 'capture' command."""
        parser = argparse.ArgumentParser(prog='capture', add_help=False)
        parser.add_argument('--iface', required=True, help='Interface name')
        parser.add_argument('--bpf', default=None, help='BPF filter')
        parser.add_argument('--custom', default=None, help='Custom filter')
        parser.add_argument('--count', type=int, default=0, help='Packet count limit')
        
        try:
            parsed = parser.parse_args(args)
            self.start_capture(parsed.iface, parsed.bpf, parsed.custom, parsed.count)
        except (SystemExit, Exception) as e:
            if not isinstance(e, SystemExit):
                print(f"Error: {e}")
    
    def _handle_read_command(self, args: list[str]) -> None:
        """Handle 'read' command."""
        parser = argparse.ArgumentParser(prog='read', add_help=False)
        parser.add_argument('--pcap', required=True, help='PCAP file path')
        parser.add_argument('--custom', default=None, help='Custom filter')
        
        try:
            parsed = parser.parse_args(args)
            self.read_pcap(parsed.pcap, parsed.custom)
        except (SystemExit, Exception) as e:
            if not isinstance(e, SystemExit):
                print(f"Error: {e}")
    
    def _handle_filter_command(self, args: list[str]) -> None:
        """Handle 'filter' command."""
        parser = argparse.ArgumentParser(prog='filter', add_help=False)
        parser.add_argument('--bpf', default=None, help='BPF filter')
        parser.add_argument('--custom', default=None, help='Custom filter')
        
        try:
            parsed = parser.parse_args(args)
            self.apply_filter(parsed.bpf, parsed.custom)
        except (SystemExit, Exception) as e:
            if not isinstance(e, SystemExit):
                print(f"Error: {e}")
    
    def _print_help(self) -> None:
        """Print help message."""
        help_text = """
MyShark CLI Commands:

  capture --iface <name> [--bpf <filter>] [--custom <expr>] [--count <n>]
      Start live packet capture
      
  read --pcap <file> [--custom <expr>]
      Read packets from pcap file
      
  list [count]
      Show recent N packets (default: 10)
      
  show <index>
      Show detailed packet information
      
  save <filename>
      Save current buffer to pcap file
      
  filter [--bpf <filter>] [--custom <expr>]
      Apply or update filters
      
  help
      Show this help message
      
  quit / exit
      Exit the CLI

Custom filter syntax:
  proto:<tcp|udp|icmp|arp>     Match protocol
  port:<number>                Match source or destination port
  ip:<address>                 Match source or destination IP
  Boolean operators: and, or, not, parentheses ()
  
  Examples:
    proto:tcp and port:80
    proto:udp and (port:53 or port:5353)
    ip:192.168.1.100 and not proto:arp
"""
        print(help_text)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MyShark - Lightweight Packet Capture Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python myshark.py interactive
  
  # One-shot read from pcap
  python myshark.py read --pcap samples/demo.pcap
  
  # Live capture (requires sudo/admin)
  sudo python myshark.py capture --iface eth0 --bpf "tcp" --custom "proto:tcp and port:80"
"""
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Operating mode')
    
    # Interactive mode
    subparsers.add_parser('interactive', help='Start interactive CLI')
    
    # Capture mode
    capture_parser = subparsers.add_parser('capture', help='Start live capture')
    capture_parser.add_argument('--iface', required=True, help='Interface name')
    capture_parser.add_argument('--bpf', default=None, help='BPF filter')
    capture_parser.add_argument('--custom', default=None, help='Custom filter expression')
    capture_parser.add_argument('--count', type=int, default=0, help='Max packets to capture')
    
    # Read mode
    read_parser = subparsers.add_parser('read', help='Read from pcap file')
    read_parser.add_argument('--pcap', required=True, help='Path to pcap file')
    read_parser.add_argument('--custom', default=None, help='Custom filter expression')
    
    args = parser.parse_args()
    
    cli = MySharkCLI()
    
    if args.mode == 'interactive':
        cli.interactive_mode()
    elif args.mode == 'capture':
        cli.start_capture(args.iface, args.bpf, args.custom, args.count)
    elif args.mode == 'read':
        cli.read_pcap(args.pcap, args.custom)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
