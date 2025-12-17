import logging

logger = logging.getLogger(__name__)

def load_pcap(pcap_path, raw=True):
    try:
        from scapy.all import rdpcap, RawPcapNgReader
        
        logger.info(f"Loading pcap file from: {pcap_path}")
        packets = rdpcap(pcap_path) if not raw else RawPcapNgReader(pcap_path)
        logger.info(f"Successfully loaded {len(packets)} packets from the pcap file.")
        return packets
    
    except ImportError:
        logger.error("Scapy library is required to load pcap files. Please install it using 'pip install scapy'.")
        return None
    except FileNotFoundError:
        logger.error(f"The specified pcap file was not found: {pcap_path}")
        return None
    except Exception as e:
        logger.error(f"An error occurred while loading the pcap file: {e}")
        return None