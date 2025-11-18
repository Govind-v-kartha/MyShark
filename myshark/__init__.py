"""
MyShark - Lightweight Packet Capture Tool

A modular Python tool for capturing, filtering, parsing, and inspecting network packets.
"""

__version__ = "1.0.0"
__author__ = "MyShark Contributors"

from .filters import compile_custom, FilterParseError
from .parser import extract_packet_info, hexdump
from .pcap_store import PcapStore

__all__ = [
    'compile_custom',
    'FilterParseError',
    'extract_packet_info',
    'hexdump',
    'PcapStore',
]
