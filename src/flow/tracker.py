"""
Flow Tracker Engine and Timeout Eviction (Mục 5.3 - UDP flow tracking và timeout).
Manages Active Flow Table, bidirectional UDP session tracking, and idle timeout eviction
for both TCP and UDP flows to prevent memory exhaustion (Section 2 & Section 5.3).
"""

from typing import Dict, List, Tuple, Optional, Any
from src.models.event import NormalizedEvent
from .model import FlowRecord, get_canonical_5tuple
from .tcp_tracker import TCPConnectionTracker, TCPState


class FlowTracker:
    """
    Central Flow Tracker managing bidirectional flow lifecycle,
    state tracking, metrics accumulation, and timeout eviction.
    """

    def __init__(
        self,
        tcp_idle_timeout: float = 300.0,
        udp_idle_timeout: float = 60.0,
        max_active_flows: int = 100000
    ):
        """
        Args:
            tcp_idle_timeout: Inactivity seconds before a TCP flow expires (default: 300s).
            udp_idle_timeout: Inactivity seconds before a UDP flow expires (default: 60s).
            max_active_flows: Maximum concurrent flows in memory to prevent RAM exhaustion.
        """
        self.tcp_idle_timeout = float(tcp_idle_timeout)
        self.udp_idle_timeout = float(udp_idle_timeout)
        self.max_active_flows = int(max_active_flows)

        # Active Flow Table: canonical_flow_id -> FlowRecord
        self.active_flows: Dict[str, FlowRecord] = {}

        # Sub-tracker for TCP state machine
        self.tcp_tracker = TCPConnectionTracker()

    def process_event(
        self,
        event: NormalizedEvent
    ) -> Tuple[NormalizedEvent, List[FlowRecord]]:
        """
        Processes a single NormalizedEvent:
            1. Evicts any timed-out flows up to current event's timestamp.
            2. Identifies or creates the canonical bidirectional flow.
            3. Updates flow statistics (packets, bytes, directions, TCP flags).
            4. Updates connection state (TCP state machine or UDP active).
            5. Enriches event with flow_id, flow_direction, and flow_state.

        Args:
            event: The parsed, decoded, and preprocessed NormalizedEvent.

        Returns:
            Tuple of (enriched_event, list_of_expired_flows_evicted)
        """
        expired_flows: List[FlowRecord] = []

        if event is None:
            return event, expired_flows

        ts = float(event.timestamp) if event.timestamp else 0.0

        # Non-IP packets cannot be mapped into standard 5-tuple flows
        if not event.network or not event.src_ip or not event.dst_ip:
            event.flow_id = None
            event.flow_direction = None
            event.flow_state = "UNTRACKED"
            return event, expired_flows

        protocol = event.network.protocol_name or "UNKNOWN"
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0

        # Calculate packet byte length (IP total length or raw payload len)
        byte_len = 0
        if event.network and event.network.total_length:
            byte_len = int(event.network.total_length)
        elif event.raw_payload_len:
            byte_len = int(event.raw_payload_len)

        # Compute stable canonical 5-tuple flow ID (Mục 5.1)
        flow_id, _, _ = get_canonical_5tuple(src_ip, dst_ip, src_port, dst_port, protocol)

        # 1. Check if the specific existing flow has exceeded idle timeout (Mục 5.3)
        timeout_limit = self.tcp_idle_timeout if protocol == "TCP" else self.udp_idle_timeout
        if flow_id in self.active_flows:
            existing_flow = self.active_flows[flow_id]
            idle_duration = ts - existing_flow.last_seen

            if idle_duration > timeout_limit:
                # Flow expired due to inactivity
                existing_flow.state = "CLOSED/TIMEOUT"
                expired_flows.append(existing_flow)
                self._evict_flow(flow_id)

        # 2. Lookup or Create FlowRecord
        if flow_id not in self.active_flows:
            # Check maximum capacity safeguard
            if len(self.active_flows) >= self.max_active_flows:
                # Evict oldest flow to maintain bounds
                oldest_id = min(self.active_flows, key=lambda fid: self.active_flows[fid].last_seen)
                evicted = self._evict_flow(oldest_id)
                if evicted:
                    evicted.state = "CLOSED/CAPACITY"
                    expired_flows.append(evicted)

            # Determine initial state
            initial_state = "NEW/HANDSHAKE" if protocol == "TCP" else "ACTIVE"

            flow = FlowRecord.create(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                timestamp=ts,
                byte_count=byte_len,
                app_protocol=event.app_protocol or "UNKNOWN",
                state=initial_state
            )
            self.active_flows[flow_id] = flow
            direction = "FORWARD"

        else:
            flow = self.active_flows[flow_id]
            direction = flow.determine_direction(src_ip, src_port)

            # Extract TCP flags if available
            tcp_flags = None
            if event.transport and hasattr(event.transport, "flags"):
                tcp_flags = event.transport.flags

            flow.update_packet(
                timestamp=ts,
                byte_count=byte_len,
                direction=direction,
                flags=tcp_flags,
                app_protocol=event.app_protocol
            )

        # 3. Connection State Machine Update (Mục 5.2 for TCP)
        if protocol == "TCP":
            tcp_flags = None
            if event.transport and hasattr(event.transport, "flags"):
                tcp_flags = event.transport.flags
            payload_len = event.raw_payload_len or 0

            self.tcp_tracker.update_state(flow, tcp_flags, payload_len, direction)

        # 4. Enrich NormalizedEvent with flow attributes
        event.flow_id = flow.flow_id
        event.flow_direction = direction
        event.flow_state = flow.state

        return event, expired_flows

    def evict_idle_flows(self, current_timestamp: float) -> List[FlowRecord]:
        """
        Scans active flow table and evicts all flows exceeding their idle timeout limit.

        Args:
            current_timestamp: Current reference epoch timestamp.

        Returns:
            List of expired FlowRecords evicted from the active table.
        """
        expired: List[FlowRecord] = []
        now = float(current_timestamp)

        for flow_id, flow in list(self.active_flows.items()):
            timeout_limit = self.tcp_idle_timeout if flow.protocol == "TCP" else self.udp_idle_timeout
            idle_time = now - flow.last_seen

            if idle_time > timeout_limit:
                flow.state = "CLOSED/TIMEOUT"
                expired.append(flow)
                self._evict_flow(flow_id)

        return expired

    def _evict_flow(self, flow_id: str) -> Optional[FlowRecord]:
        """Internal helper removing a flow from active table and clearing tracker context."""
        flow = self.active_flows.pop(flow_id, None)
        self.tcp_tracker.remove_flow(flow_id)
        return flow

    def flush_all(self) -> List[FlowRecord]:
        """
        Flushes and returns all remaining active flows (e.g. at end of stream/file).
        """
        all_flows = list(self.active_flows.values())
        self.active_flows.clear()
        self.tcp_tracker._states.clear()
        return all_flows
