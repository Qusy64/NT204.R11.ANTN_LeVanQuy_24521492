"""
Base Packet Capture Interface.
Defines the abstract interface for all packet sources (PCAP file, Live Interface, etc.)
Ensuring a unified ingestion stream without branching parsers.
"""

from abc import ABC, abstractmethod
from typing import Generator, Tuple, Any


class BasePacketSource(ABC):
    """
    Abstract base class for packet capture sources.
    Every packet source must yield tuples of (timestamp: float, raw_packet: Any).
    """

    @abstractmethod
    def read_packets(self) -> Generator[Tuple[float, Any], None, None]:
        """
        Yields packets one by one as a generator to minimize memory consumption.
        
        Returns:
            Generator yielding (timestamp: float, raw_packet: Scapy Packet).
        """
        pass
