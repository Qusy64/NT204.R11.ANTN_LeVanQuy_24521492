"""
Parsing Pipeline & Error Handling Module.
Coordinates the sequential dissection of raw packets across network (L3),
transport (L4), DPI detection, and application (L7) layers into NormalizedEvent.
Guarantees zero-crash execution through defensive exception boundaries.
"""

from typing import Any, Optional, Iterable, Generator, Tuple
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from src.models.event import NormalizedEvent
from src.parsers.network import parse_ipv4
from src.parsers.transport import parse_transport
from src.parsers.app_detector import detect_app_protocol
from src.parsers.http_parser import parse_http
from src.parsers.dns_parser import parse_dns
from src.parsers.smtp_parser import parse_smtp


class ParsingPipeline:
    """
    Central pipeline controller that orchestrates protocol parsers.
    Processes packets sequentially and outputs standardized NormalizedEvent objects.
    """

    def process_packet(
        self,
        packet_id: int,
        timestamp: Any,
        packet: Any
    ) -> NormalizedEvent:
        """
        Dissects a single raw packet through the protocol hierarchy:
            1. Initializes NormalizedEvent.
            2. Parses Layer 3 (IPv4). If non-IPv4, halts upper-layer parsing safely.
            3. Parses Layer 4 (TCP / UDP).
            4. Executes DPI detection (HTTP, DNS, SMTP, UNKNOWN).
            5. Dissects Layer 7 (HTTP / DNS / SMTP) based on DPI determination.
            6. Catches all exceptions to ensure zero process crash.

        Args:
            packet_id: Monotonically increasing integer packet identifier.
            timestamp: Packet capture epoch timestamp (float or numeric).
            packet: Scapy packet object or raw bytes.

        Returns:
            NormalizedEvent dataclass instance populated with all parsed layers.
        """
        # Safe timestamp conversion
        ts_val = 0.0
        if timestamp is not None:
            try:
                ts_val = float(timestamp)
            except (ValueError, TypeError):
                ts_val = 0.0

        event = NormalizedEvent(packet_id=int(packet_id), timestamp=ts_val)

        # 0. Null check
        if packet is None:
            event.is_malformed = True
            event.errors.append("Null packet received")
            return event

        # Convert raw bytes to Scapy packet if necessary
        scapy_pkt = packet
        if isinstance(packet, (bytes, bytearray)):
            try:
                scapy_pkt = IP(packet)
            except Exception:
                try:
                    scapy_pkt = Ether(packet)
                except Exception as exc:
                    event.is_malformed = True
                    event.errors.append(f"Raw packet decode failed: {str(exc)}")
                    return event

        try:
            # 1. Layer 3: IPv4 Network Parsing
            ipv4_info = parse_ipv4(scapy_pkt, event)
            if ipv4_info is None:
                # Non-IPv4 packet (e.g. ARP, IPv6). Upper layers not applicable.
                event.app_protocol = "UNKNOWN"
                return event

            # 2. Layer 4: Transport Parsing (TCP / UDP)
            trans_info = parse_transport(scapy_pkt, event)
            if trans_info is None:
                # E.g. ICMP or unsupported transport. Upper layers not applicable.
                event.app_protocol = "UNKNOWN"
                return event

            # 3. DPI Layer: Application Protocol Detection
            detected_proto = detect_app_protocol(scapy_pkt, event)

            # 4. Layer 7: Application Protocol Parsing
            if detected_proto == "HTTP":
                parse_http(scapy_pkt, event)
            elif detected_proto == "DNS":
                parse_dns(scapy_pkt, event)
            elif detected_proto == "SMTP":
                parse_smtp(scapy_pkt, event)

        except Exception as exc:
            event.is_malformed = True
            event.errors.append(f"Pipeline processing error: {str(exc)}")

        return event

    def process_stream(
        self,
        packet_source: Iterable[Tuple[float, Any]],
        start_id: int = 1
    ) -> Generator[NormalizedEvent, None, None]:
        """
        Processes an iterable stream of (timestamp, packet) tuples sequentially.

        Args:
            packet_source: Iterable yielding (timestamp, raw_packet).
            start_id: Initial integer ID for packet numbering (default: 1).

        Yields:
            NormalizedEvent for each packet in the stream.
        """
        curr_id = start_id
        for ts, pkt in packet_source:
            yield self.process_packet(curr_id, ts, pkt)
            curr_id += 1


# Default singleton instance and convenience module-level function
_default_pipeline = ParsingPipeline()


def process_packet(packet_id: int, timestamp: Any, packet: Any) -> NormalizedEvent:
    """
    Convenience function to dissect a packet using the default ParsingPipeline instance.
    """
    return _default_pipeline.process_packet(packet_id, timestamp, packet)
