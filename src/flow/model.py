"""
Flow Data Model and Canonical 5-Tuple Resolver (Mục 5.1 & Mục 5.4).
Defines FlowRecord, FlowStatistics, canonical bidirectional 5-tuple sorting,
and direction resolution (FORWARD / BACKWARD) compliant with RFC / NetFlow standards.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, Tuple


def get_canonical_5tuple(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str
) -> Tuple[str, Tuple[str, int], Tuple[str, int]]:
    """
    Computes a canonical, order-independent 5-tuple and a stable flow_id.
    Guarantees that traffic from A->B and B->A generates the EXACT same flow_id.

    Args:
        src_ip: Source IPv4 address string.
        dst_ip: Destination IPv4 address string.
        src_port: Source port integer.
        dst_port: Destination port integer.
        protocol: Transport protocol string (e.g. "TCP", "UDP").

    Returns:
        Tuple of (flow_id, endpoint_min, endpoint_max)
    """
    proto = str(protocol).strip().upper() if protocol else "UNKNOWN"
    s_ip = str(src_ip).strip() if src_ip else "0.0.0.0"
    d_ip = str(dst_ip).strip() if dst_ip else "0.0.0.0"
    s_port = int(src_port) if src_port is not None else 0
    d_port = int(dst_port) if dst_port is not None else 0

    ep1 = (s_ip, s_port)
    ep2 = (d_ip, d_port)

    # Deterministic canonical ordering (min endpoint first)
    if ep1 <= ep2:
        ep_min, ep_max = ep1, ep2
    else:
        ep_min, ep_max = ep2, ep1

    flow_id = f"{proto.lower()}_{ep_min[0]}:{ep_min[1]}_{ep_max[0]}:{ep_max[1]}"
    return flow_id, ep_min, ep_max


@dataclass
class FlowStatistics:
    """
    Minimum statistical counters on each flow compliant with Mục 5.4.
    Tracks overall and directional (forward/backward) packet and byte counts,
    as well as TCP control flag counters.
    """
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0


@dataclass
class FlowRecord:
    """
    Standardized Bidirectional Flow Record (Mục 5.1 & Mục 5.4).
    Maintains flow identity, endpoints, timing, state, and accumulated metrics.
    """
    flow_id: str
    protocol: str
    application_protocol: str = "UNKNOWN"
    endpoint_a: str = ""           # Initiator (src_ip:src_port of first observed packet)
    endpoint_b: str = ""           # Responder (dst_ip:dst_port of first observed packet)
    start_time: float = 0.0
    last_seen: float = 0.0
    duration: float = 0.0
    state: str = "NEW/HANDSHAKE"    # Logical connection state (Mục 5.2)
    stats: FlowStatistics = field(default_factory=FlowStatistics)

    @classmethod
    def create(
        cls,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        timestamp: float,
        byte_count: int,
        app_protocol: str = "UNKNOWN",
        state: str = "NEW/HANDSHAKE"
    ) -> "FlowRecord":
        """Factory method initializing a new bidirectional flow record."""
        flow_id, _, _ = get_canonical_5tuple(src_ip, dst_ip, src_port, dst_port, protocol)
        ts = float(timestamp) if timestamp is not None else 0.0
        proto_clean = str(protocol).strip().upper() if protocol else "UNKNOWN"

        record = cls(
            flow_id=flow_id,
            protocol=proto_clean,
            application_protocol=str(app_protocol).strip().upper() if app_protocol else "UNKNOWN",
            endpoint_a=f"{src_ip}:{src_port}",
            endpoint_b=f"{dst_ip}:{dst_port}",
            start_time=ts,
            last_seen=ts,
            duration=0.0,
            state=state,
            stats=FlowStatistics(
                packet_count=1,
                byte_count=int(byte_count),
                forward_packet_count=1,
                backward_packet_count=0,
                forward_byte_count=int(byte_count),
                backward_byte_count=0
            )
        )
        return record

    def determine_direction(self, src_ip: str, src_port: int) -> str:
        """
        Determines whether a packet is FORWARD (from initiator) or BACKWARD (from responder).

        Args:
            src_ip: Source IP of the packet.
            src_port: Source port of the packet.

        Returns:
            "FORWARD" or "BACKWARD"
        """
        pkt_src = f"{src_ip}:{src_port}"
        if pkt_src == self.endpoint_a:
            return "FORWARD"
        return "BACKWARD"

    def update_packet(
        self,
        timestamp: float,
        byte_count: int,
        direction: str,
        flags: Optional[Dict[str, bool]] = None,
        app_protocol: Optional[str] = None
    ) -> None:
        """Updates flow timing, counters, and statistics with a new packet."""
        ts = float(timestamp) if timestamp is not None else self.last_seen
        if ts > self.last_seen:
            self.last_seen = ts
        self.duration = round(max(0.0, self.last_seen - self.start_time), 6)

        bytes_len = int(byte_count) if byte_count is not None else 0
        self.stats.packet_count += 1
        self.stats.byte_count += bytes_len

        if direction == "FORWARD":
            self.stats.forward_packet_count += 1
            self.stats.forward_byte_count += bytes_len
        else:
            self.stats.backward_packet_count += 1
            self.stats.backward_byte_count += bytes_len

        # Update TCP flag counters
        if flags and isinstance(flags, dict):
            if flags.get("SYN"):
                self.stats.syn_count += 1
            if flags.get("ACK"):
                self.stats.ack_count += 1
            if flags.get("FIN"):
                self.stats.fin_count += 1
            if flags.get("RST"):
                self.stats.rst_count += 1

        # Update application protocol if identified later
        if app_protocol and app_protocol != "UNKNOWN":
            self.application_protocol = str(app_protocol).strip().upper()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the flow record into a JSON-compatible dictionary (Mục 5.4)."""
        data = asdict(self)
        # Flatten stats into the root dictionary for convenient tabular & JSON Lines analysis
        stats_dict = data.pop("stats", {})
        data.update(stats_dict)
        return data
