"""
Packet storage and PCAP file handling.

Provides an in-memory circular buffer for storing captured packets
and utilities for saving/loading PCAP files.
"""

from collections import deque
from typing import Optional, List
import logging


logger = logging.getLogger(__name__)


class PacketBuffer:
    """In-memory circular buffer for storing parsed packets."""
    
    def __init__(self, maxlen: int = 500):
        """
        Initialize circular buffer.
        
        Args:
            maxlen: Maximum number of packets to store (default 500)
        """
        self.maxlen = maxlen
        self.buffer: deque = deque(maxlen=maxlen)
        self.scapy_packets: deque = deque(maxlen=maxlen)  # Store original Scapy packets
    
    def append(self, parsed_packet, scapy_packet=None):
        """
        Append a packet to the buffer.
        
        Args:
            parsed_packet: ParsedPacket object from parser.extract_packet_info()
            scapy_packet: Original Scapy packet (for PCAP saving)
        """
        self.buffer.append(parsed_packet)
        self.scapy_packets.append(scapy_packet)
    
    def get(self, index: int) -> Optional[tuple]:
        """
        Get packet at index (0 = oldest, -1 = newest).
        
        Returns:
            Tuple of (parsed_packet, scapy_packet) or None
        """
        try:
            if -len(self.buffer) <= index < len(self.buffer):
                return self.buffer[index], self.scapy_packets[index]
        except (IndexError, TypeError):
            pass
        
        return None
    
    def get_all(self) -> List[tuple]:
        """Get all packets as list of (parsed_packet, scapy_packet) tuples."""
        return list(zip(self.buffer, self.scapy_packets))
    
    def get_recent(self, n: int = 10) -> List[tuple]:
        """
        Get the most recent n packets.
        
        Args:
            n: Number of recent packets to retrieve
        
        Returns:
            List of (parsed_packet, scapy_packet) tuples
        """
        all_packets = self.get_all()
        return all_packets[-n:] if all_packets else []
    
    def clear(self):
        """Clear the buffer."""
        self.buffer.clear()
        self.scapy_packets.clear()
    
    def count(self) -> int:
        """Return number of packets in buffer."""
        return len(self.buffer)
    
    def save_to_pcap(self, filename: str) -> bool:
        """
        Save all packets to a PCAP file.
        
        Args:
            filename: Output PCAP filename
        
        Returns:
            True if successful, False otherwise
        """
        try:
            from scapy.all import wrpcap
            
            packets = [pkt for pkt in self.scapy_packets if pkt is not None]
            if not packets:
                logger.warning("No packets to save")
                return False
            
            wrpcap(filename, packets)
            logger.info(f"Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving PCAP: {e}")
            return False


def load_pcap(filename: str) -> Optional[list]:
    """
    Load packets from a PCAP file.
    
    Args:
        filename: Input PCAP filename
    
    Returns:
        List of Scapy packet objects or None on error
    """
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap(filename)
        logger.info(f"Loaded {len(packets)} packets from {filename}")
        return packets
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {filename}")
        return None
    except Exception as e:
        logger.error(f"Error loading PCAP: {e}")
        return None
