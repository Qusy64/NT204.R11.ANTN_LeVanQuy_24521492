"""
Live Interface Packet Source.
Captures live network traffic from a selected network interface.
"""

import time
import queue
from typing import Generator, Tuple, Any, Optional
from scapy.all import AsyncSniffer
from .base import BasePacketSource


class LiveCapture(BasePacketSource):
    """Captures packets live from a network interface without accumulating in RAM."""

    def __init__(
        self,
        interface: Optional[str] = None,
        count: Optional[int] = None,
        bpf_filter: Optional[str] = None,
    ):
        self.interface = interface
        self.count = count
        self.bpf_filter = bpf_filter

    def read_packets(self) -> Generator[Tuple[float, Any], None, None]:
        """
        Captures packets using an asynchronous sniffer and a thread-safe queue.
        Records capture timestamp at the exact moment the packet arrives.
        
        Yields:
            (timestamp: float, raw_packet: Scapy Packet)
        """
        packet_queue: queue.Queue = queue.Queue()

        def packet_handler(pkt):
            capture_time = time.time()
            packet_queue.put((capture_time, pkt))

        # Start Scapy's AsyncSniffer with store=False to avoid RAM accumulation
        sniffer = AsyncSniffer(
            iface=self.interface,
            count=self.count or 0,
            filter=self.bpf_filter,
            prn=packet_handler,
            store=False,
        )
        sniffer.start()

        packets_yielded = 0
        try:
            while sniffer.running or not packet_queue.empty():
                try:
                    item = packet_queue.get(timeout=0.5)
                    yield item
                    packets_yielded += 1
                    if self.count and packets_yielded >= self.count:
                        break
                except queue.Empty:
                    continue
        finally:
            if sniffer.running:
                sniffer.stop()
