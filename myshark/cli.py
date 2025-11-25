#!/usr/bin/env python3
"""
MyShark - Lightweight Packet Capture and Inspection Tool

CLI entrypoint with commands for capturing, filtering, viewing, and saving packets.
"""

import os
import sys
import logging
import signal
from typing import Optional
import click

from myshark.filters import compile_custom, ParseError as FilterParseError
from myshark.parser import extract_packet_info, hexdump
from myshark.pcap_store import PacketBuffer, load_pcap


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class CaptureManager:
    """Manages packet capture, filtering, and storage."""
    
    def __init__(self, buffer_size: int = 500):
        self.buffer = PacketBuffer(maxlen=buffer_size)
        self.capturing = False
        self.custom_filter = None
        self.bpf_filter = ""
    
    def start_capture(self, iface: Optional[str], bpf_filter: str, custom_filter: str):
        """
        Start live packet capture.
        
        Args:
            iface: Interface name (None = default)
            bpf_filter: BPF filter string
            custom_filter: Custom post-capture filter expression
        """
        try:
            from scapy.all import sniff, conf
        except ImportError:
            logger.error("Scapy not installed. Run: pip install -r requirements.txt")
            return
        
        # Check privileges (Unix-like systems only)
        if hasattr(os, 'geteuid'):
            if os.geteuid() != 0:
                logger.error("Insufficient privileges for live capture — use 'sudo' or run with Administrator rights")
                logger.info("Falling back to manual packet mode or use read --pcap to load from file")
                return
        
        # Compile custom filter if provided
        if custom_filter:
            try:
                self.custom_filter = compile_custom(custom_filter)
            except FilterParseError as e:
                logger.error(f"Invalid custom filter: {e}")
                return
        
        self.bpf_filter = bpf_filter
        self.capturing = True
        
        logger.info(f"Starting capture on {iface or 'default interface'}")
        if bpf_filter:
            logger.info(f"  BPF filter: {bpf_filter}")
        if custom_filter:
            logger.info(f"  Custom filter: {custom_filter}")
        
        try:
            # Callback for each packet
            def packet_callback(pkt):
                if self.capturing:
                    parsed = extract_packet_info(pkt)
                    
                    # Apply custom filter
                    if self.custom_filter and not self.custom_filter(pkt):
                        return
                    
                    self.buffer.append(parsed, pkt)
                    logger.debug(f"Captured: {parsed.summary}")
            
            # Start sniffing
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=packet_callback,
                store=False,
                stop_filter=lambda x: not self.capturing
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.capturing = False
    
    def stop_capture(self):
        """Stop ongoing capture."""
        self.capturing = False
        logger.info("Capture stopped")
    
    def load_from_pcap(self, filename: str, custom_filter: str):
        """
        Load packets from a PCAP file.
        
        Args:
            filename: PCAP file path
            custom_filter: Custom post-load filter expression
        """
        packets = load_pcap(filename)
        if not packets:
            logger.error(f"Failed to load {filename}")
            return
        
        # Compile custom filter if provided
        if custom_filter:
            try:
                custom_filter_func = compile_custom(custom_filter)
            except FilterParseError as e:
                logger.error(f"Invalid custom filter: {e}")
                return
        else:
            custom_filter_func = None
        
        logger.info(f"Processing {len(packets)} packets from {filename}")
        
        for pkt in packets:
            parsed = extract_packet_info(pkt)
            
            # Apply custom filter
            if custom_filter_func and not custom_filter_func(pkt):
                continue
            
            self.buffer.append(parsed, pkt)
        
        logger.info(f"Loaded {self.buffer.count()} packets (after filtering)")


# Global capture manager
manager = CaptureManager()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """MyShark - Lightweight Packet Capture and Inspection Tool"""
    if ctx.invoked_subcommand is None:
        # Interactive mode if no subcommand
        repl_mode()


@cli.command()
@click.option("--iface", "-i", default=None, help="Interface name (default: system default)")
@click.option("--bpf", default="", help="BPF filter (e.g., 'tcp', 'port 80')")
@click.option("--custom", default="", help="Custom filter (e.g., 'proto:tcp and port:80')")
@click.option("--timeout", type=int, default=None, help="Capture timeout in seconds")
def capture(iface: Optional[str], bpf: str, custom: str, timeout: Optional[int]):
    """Start live packet capture."""
    try:
        manager.start_capture(iface, bpf, custom)
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
        manager.stop_capture()


@cli.command()
@click.argument("pcap_file")
@click.option("--custom", default="", help="Custom filter (e.g., 'proto:tcp and port:80')")
def read(pcap_file: str, custom: str):
    """Load and process packets from a PCAP file."""
    manager.load_from_pcap(pcap_file, custom)
    list_packets(10)


@cli.command()
@click.argument("count", type=int, default=10, required=False)
def list(count: int):
    """List recent captured packets."""
    list_packets(count)


@cli.command()
@click.argument("packet_id", type=int)
def show(packet_id: int):
    """Show detailed information about a packet."""
    show_packet(packet_id)


@cli.command()
@click.option("--bpf", default="", help="BPF filter")
@click.option("--custom", default="", help="Custom filter")
def filter(bpf: str, custom: str):
    """Apply filters to loaded packets."""
    if not bpf and not custom:
        logger.error("Provide at least one filter (--bpf or --custom)")
        return
    
    logger.info("Filters applied to subsequent operations")
    manager.bpf_filter = bpf
    if custom:
        try:
            manager.custom_filter = compile_custom(custom)
        except FilterParseError as e:
            logger.error(f"Invalid custom filter: {e}")


@cli.command()
@click.argument("output_file")
def save(output_file: str):
    """Save captured packets to a PCAP file."""
    success = manager.buffer.save_to_pcap(output_file)
    if success:
        click.echo(f"✓ Saved {manager.buffer.count()} packets to {output_file}")
    else:
        click.echo(f"✗ Failed to save packets")


@cli.command()
def stats():
    """Show capture statistics."""
    count = manager.buffer.count()
    click.echo(f"Packets in buffer: {count}")
    if count > 0:
        click.echo(f"Buffer size: {manager.buffer.maxlen}")


@cli.command()
def quit():
    """Exit the tool."""
    manager.stop_capture()
    click.echo("Goodbye!")
    sys.exit(0)


# REPL interactive mode functions

def list_packets(count: int):
    """Display recent packets in table format."""
    packets = manager.buffer.get_recent(count)
    
    if not packets:
        logger.info("No packets captured yet")
        return
    
    # Header
    click.echo("\n" + "=" * 120)
    click.echo(f"{'#':<4} {'Time':<19} {'Src':<20} {'Dst':<20} {'Proto':<6} {'Summary':<50}")
    click.echo("-" * 120)
    
    # Get base index (accounting for circular buffer)
    base_idx = max(0, manager.buffer.count() - count)
    
    for i, (parsed, _) in enumerate(packets):
        idx = base_idx + i
        time_str = parsed.timestamp_iso.split("T")[1][:8] if parsed.timestamp_iso else "N/A"
        src = f"{parsed.src_ip}:{parsed.sport}" if parsed.src_ip and parsed.sport else parsed.src_ip or "N/A"
        dst = f"{parsed.dst_ip}:{parsed.dport}" if parsed.dst_ip and parsed.dport else parsed.dst_ip or "N/A"
        proto = parsed.l4_proto or "?"
        summary = parsed.summary[:50]
        
        click.echo(f"{idx:<4} {time_str:<19} {src:<20} {dst:<20} {proto:<6} {summary:<50}")
    
    click.echo("=" * 120 + "\n")


def show_packet(packet_id: int):
    """Display full details of a specific packet."""
    result = manager.buffer.get(packet_id)
    
    if result is None:
        logger.error(f"Packet {packet_id} not found")
        return
    
    parsed, scapy_pkt = result
    
    click.echo("\n" + "=" * 80)
    click.echo(f"Packet #{packet_id}")
    click.echo("=" * 80)
    
    # Timestamp
    click.echo(f"Timestamp: {parsed.timestamp_iso}")
    
    # Link layer
    click.echo(f"\nLink Layer:")
    # Show detected link type (Ether, Loopback, RadioTap, etc.) and MACs if present
    click.echo(f"  Link Type: {parsed.link_type or 'Unknown'}")
    if parsed.src_mac and parsed.dst_mac:
        click.echo(f"  Source MAC: {parsed.src_mac}")
        click.echo(f"  Dest MAC:   {parsed.dst_mac}")
    
    # Network layer
    click.echo(f"\nNetwork Layer:")
    if parsed.src_ip and parsed.dst_ip:
        click.echo(f"  Source IP: {parsed.src_ip}")
        click.echo(f"  Dest IP:   {parsed.dst_ip}")
    
    # Transport layer
    if parsed.l4_proto:
        click.echo(f"\nTransport Layer ({parsed.l4_proto}):")
        if parsed.sport and parsed.dport:
            click.echo(f"  Source Port: {parsed.sport}")
            click.echo(f"  Dest Port:   {parsed.dport}")
        if parsed.tcp_flags:
            click.echo(f"  TCP Flags: {', '.join(parsed.tcp_flags)}")
    
    # Application layer
    if parsed.dns_queries:
        click.echo(f"\nDNS:")
        for query in parsed.dns_queries:
            click.echo(f"  Query: {query}")
    
    if parsed.http_host:
        click.echo(f"\nHTTP:")
        click.echo(f"  Host: {parsed.http_host}")
        if parsed.http_path:
            click.echo(f"  Path: {parsed.http_path}")
    
    # Protocol stack
    click.echo(f"\nProtocol Stack: {' / '.join(parsed.layers)}")
    
    # Hex dumps
    click.echo(f"\nFull Packet Hex Dump ({len(parsed.raw_bytes)} bytes):")
    click.echo("-" * 80)
    if parsed.raw_bytes:
        click.echo(hexdump(parsed.raw_bytes))
    
    if parsed.payload_bytes:
        click.echo(f"\nPayload Hex Dump ({len(parsed.payload_bytes)} bytes):")
        click.echo("-" * 80)
        click.echo(hexdump(parsed.payload_bytes))
    
    click.echo("=" * 80 + "\n")


def repl_mode():
    """Interactive REPL mode."""
    click.echo("MyShark Interactive Mode")
    click.echo("Type 'help' for available commands, or 'quit' to exit\n")
    
    while True:
        try:
            cmd_line = input("> ").strip()
            
            if not cmd_line:
                continue
            
            parts = cmd_line.split()
            cmd = parts[0].lower()
            args = parts[1:]
            
            if cmd == "help":
                click.echo("""
Available commands:
  capture [--iface IFACE] [--bpf FILTER]  Start live capture
  read PCAP_FILE                          Load from PCAP file
  list [N]                                List recent N packets (default 10)
  show <ID>                               Show packet details
  filter [--bpf FILTER] [--custom EXPR]  Apply filters
  save <FILE.PCAP>                        Save to PCAP file
  stats                                   Show statistics
  quit                                    Exit
                """)
            elif cmd == "quit":
                manager.stop_capture()
                click.echo("Goodbye!")
                break
            elif cmd == "list":
                n = int(args[0]) if args else 10
                list_packets(n)
            elif cmd == "show":
                if args:
                    try:
                        packet_id = int(args[0])
                        show_packet(packet_id)
                    except ValueError:
                        logger.error("Packet ID must be an integer")
            elif cmd == "stats":
                click.echo(f"Packets in buffer: {manager.buffer.count()}")
            else:
                logger.error(f"Unknown command: {cmd}")
        
        except KeyboardInterrupt:
            click.echo("\nUse 'quit' to exit")
        except Exception as e:
            logger.error(f"Error: {e}")


if __name__ == "__main__":
    cli()
