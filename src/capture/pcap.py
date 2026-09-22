"""
PCAP File Packet Source.
Streams packets from an offline .pcap file using Scapy's PcapReader (lazy loading).
"""

import os
from typing import Generator, Tuple, Any
from scapy.all import PcapReader
from .base import BasePacketSource


class PcapCapture(BasePacketSource):
    """Reads packets sequentially from a PCAP file using a streaming generator."""

    def __init__(self, filepath: str):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        self.filepath = filepath

    def read_packets(self) -> Generator[Tuple[float, Any], None, None]:
        """
        Reads packets from the PCAP file one by one without loading the entire file into RAM.
        
        Yields:
            (timestamp: float, raw_packet: Scapy Packet)
        """
        with PcapReader(self.filepath) as reader:
            for packet in reader:
                # packet.time is a decimal/float representing the epoch timestamp recorded in PCAP
                timestamp = float(packet.time) if hasattr(packet, "time") else 0.0
                yield timestamp, packet
