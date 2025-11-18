"""
In-memory circular buffer for packet storage with save/load capabilities.
"""

import logging
from collections import deque
from typing import List, Optional, Dict, Any
from scapy.all import wrpcap, rdpcap, Packet


logger = logging.getLogger(__name__)


class PcapStore:
    """
    In-memory circular buffer for storing parsed packets.
    
    Supports:
    - Append packet information
    - Get packet by index
    - Save to pcap file
    - Load from pcap file
    """
    
    def __init__(self, maxlen: int = 500):
        """
        Initialize the circular buffer.
        
        Args:
            maxlen: Maximum number of packets to store (default 500)
        """
        self.maxlen = maxlen
        self.buffer: deque = deque(maxlen=maxlen)
        self.packets: deque = deque(maxlen=maxlen)  # Raw Scapy packets
        self.lock = None  # Can add threading.Lock if needed
    
    def append(self, parsed_info: Dict[str, Any], raw_packet: Optional[Packet] = None) -> int:
        """
        Append packet info to buffer.
        
        Args:
            parsed_info: Dictionary with parsed packet information
            raw_packet: Original Scapy packet object
            
        Returns:
            Index of the added packet
        """
        self.buffer.append(parsed_info)
        self.packets.append(raw_packet)
        return len(self.buffer) - 1
    
    def get(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Get packet info by index.
        
        Args:
            index: Packet index (0-based, relative to start of current buffer)
            
        Returns:
            Parsed packet info dict, or None if index out of range
        """
        if 0 <= index < len(self.buffer):
            return self.buffer[index]
        return None
    
    def get_packet(self, index: int) -> Optional[Packet]:
        """
        Get raw Scapy packet by index.
        
        Args:
            index: Packet index (0-based, relative to start of current buffer)
            
        Returns:
            Raw packet, or None if index out of range
        """
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def get_all(self) -> List[Dict[str, Any]]:
        """Get all packet info in buffer."""
        return list(self.buffer)
    
    def get_all_packets(self) -> List[Packet]:
        """Get all raw packets in buffer."""
        return list(self.packets)
    
    def clear(self) -> None:
        """Clear the buffer."""
        self.buffer.clear()
        self.packets.clear()
    
    def length(self) -> int:
        """Get current number of packets in buffer."""
        return len(self.buffer)
    
    def save_to_pcap(self, filename: str) -> None:
        """
        Save all packets in buffer to a pcap file.
        
        Args:
            filename: Output pcap filename
            
        Raises:
            IOError: If file cannot be written
        """
        packets = self.get_all_packets()
        if not packets:
            logger.warning(f"No packets to save to {filename}")
            return
        
        try:
            wrpcap(filename, packets)
            logger.info(f"Saved {len(packets)} packets to {filename}")
        except Exception as e:
            logger.error(f"Error saving pcap: {e}")
            raise
    
    def load_from_pcap(self, filename: str, clear_first: bool = True) -> int:
        """
        Load packets from a pcap file into the buffer.
        
        Args:
            filename: Input pcap filename
            clear_first: Whether to clear buffer before loading (default True)
            
        Returns:
            Number of packets loaded
            
        Raises:
            IOError: If file cannot be read
        """
        if clear_first:
            self.clear()
        
        try:
            packets = rdpcap(filename)
            count = 0
            for pkt in packets:
                # For now, just store the raw packet; caller can parse if needed
                self.append({'raw_packet': bytes(pkt)}, raw_packet=pkt)
                count += 1
            logger.info(f"Loaded {count} packets from {filename}")
            return count
        except Exception as e:
            logger.error(f"Error loading pcap: {e}")
            raise
