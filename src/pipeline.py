"""
Parsing & Flow Pipeline Module (Mục 1 & Mục 2).
Coordinates the complete end-to-end processing chain:
  Packet Source -> Parser (BT1) -> Decoder (Mục 3) -> Preprocessor (Mục 4) -> Flow Tracker (Mục 5) -> Output.
Guarantees 100% zero-crash resilience through defensive exception boundaries.
"""

from typing import Any, Optional, Iterable, Generator, Tuple, List
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from src.models.event import NormalizedEvent
from src.parsers.network import parse_ipv4
from src.parsers.transport import parse_transport
from src.parsers.app_detector import detect_app_protocol
from src.parsers.http_parser import parse_http
from src.parsers.dns_parser import parse_dns
from src.parsers.smtp_parser import parse_smtp

from src.decoders import DecoderEngine
from src.preprocessor import PreprocessorEngine
from src.flow import FlowTracker, FlowRecord


class ParsingPipeline:
    """
    Central pipeline orchestrator chaining:
        Parser (L3/L4/DPI/L7) -> Decoder -> Preprocessor -> Flow Tracker.
    """

    def __init__(
        self,
        tcp_idle_timeout: float = 300.0,
        udp_idle_timeout: float = 60.0,
        drop_invalid: bool = False,
    ):
        """
        Args:
            tcp_idle_timeout: Inactivity seconds before a TCP flow expires.
            udp_idle_timeout: Inactivity seconds before a UDP flow expires.
            drop_invalid: Policy flag; if True, invalid events are tagged action 'DROP'.
        """
        self.decoder = DecoderEngine()
        self.preprocessor = PreprocessorEngine(drop_invalid=drop_invalid)
        self.flow_tracker = FlowTracker(
            tcp_idle_timeout=tcp_idle_timeout,
            udp_idle_timeout=udp_idle_timeout
        )
        self.expired_flows: List[FlowRecord] = []

    def process_packet(
        self,
        packet_id: int,
        timestamp: Any,
        packet: Any
    ) -> NormalizedEvent:
        """
        Processes a single raw packet through the complete 5-stage pipeline:
            1. Initializes NormalizedEvent.
            2. Layer 3 & Layer 4 & DPI & Layer 7 protocol parsing.
            3. Decoder: URL, HTML, MIME Base64/Quoted-Printable, Character safe decode.
            4. Preprocessor: Validation (valid/partial/invalid), Normalization, Metadata.
            5. Flow/Connection Tracker: 5-tuple, direction, TCP state machine, metrics.

        Args:
            packet_id: Monotonically increasing packet identifier.
            timestamp: Epoch timestamp of capture.
            packet: Raw Scapy packet or bytes.

        Returns:
            Fully enriched NormalizedEvent.
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
            # Still run preprocessor to assign invalid metadata
            event = self.preprocessor.preprocess(event)
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
                    event = self.preprocessor.preprocess(event)
                    return event

        try:
            # Stage 1: Protocol Dissection (L3, L4, DPI, L7)
            ipv4_info = parse_ipv4(scapy_pkt, event)
            if ipv4_info is not None:
                trans_info = parse_transport(scapy_pkt, event)
                if trans_info is not None:
                    detected_proto = detect_app_protocol(scapy_pkt, event)
                    if detected_proto == "HTTP":
                        parse_http(scapy_pkt, event)
                    elif detected_proto == "DNS":
                        parse_dns(scapy_pkt, event)
                    elif detected_proto == "SMTP":
                        parse_smtp(scapy_pkt, event)
                else:
                    event.app_protocol = "UNKNOWN"
            else:
                event.app_protocol = "UNKNOWN"

        except Exception as exc:
            event.is_malformed = True
            event.errors.append(f"Dissection error: {str(exc)}")

        try:
            # Stage 2: Decoder Module (Mục 3)
            event = self.decoder.decode(event)

            # Stage 3: Preprocessor Module (Mục 4)
            event = self.preprocessor.preprocess(event)

            # Stage 4: Flow Tracker Engine (Mục 5)
            event, expired = self.flow_tracker.process_event(event)
            if expired:
                self.expired_flows.extend(expired)

        except Exception as exc:
            event.errors.append(f"Post-processing pipeline error: {str(exc)}")

        return event

    def process_stream(
        self,
        packet_source: Iterable[Tuple[float, Any]],
        start_id: int = 1
    ) -> Generator[NormalizedEvent, None, None]:
        """
        Processes an iterable stream of (timestamp, packet) tuples sequentially.

        Yields:
            Enriched NormalizedEvent for each packet.
        """
        curr_id = start_id
        for ts, pkt in packet_source:
            yield self.process_packet(curr_id, ts, pkt)
            curr_id += 1

    def flush_flows(self) -> List[FlowRecord]:
        """
        Flushes all active flows remaining in memory and returns all recorded flows.
        """
        remaining = self.flow_tracker.flush_all()
        all_flows = self.expired_flows + remaining
        self.expired_flows = []
        return all_flows


# Default singleton instance and convenience module-level function
_default_pipeline = ParsingPipeline()


def process_packet(packet_id: int, timestamp: Any, packet: Any) -> NormalizedEvent:
    """Convenience function to dissect a packet using the default ParsingPipeline instance."""
    return _default_pipeline.process_packet(packet_id, timestamp, packet)
