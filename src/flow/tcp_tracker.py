"""
TCP Connection State Machine (Mục 5.2 - TCP connection tracking).
Tracks logical connection states: NEW/HANDSHAKE, ESTABLISHED, CLOSING, and CLOSED/RESET
using SYN, ACK, FIN, and RST control flags compliant with RFC 793 and Mục 5.2.
"""

from typing import Dict, Any, Optional
from .model import FlowRecord


class TCPState:
    """Standard logical TCP connection states required by Mục 5.2."""
    HANDSHAKE = "NEW/HANDSHAKE"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED_RESET = "CLOSED/RESET"


class TCPConnectionTracker:
    """
    Finite State Machine (FSM) managing TCP connection lifecycle per flow.
    Handles 3-way handshakes, data transfer, graceful FIN/ACK teardown,
    and immediate RST termination, with support for packets without payload.
    """

    def __init__(self):
        # Maps flow_id -> per-flow tracking context
        self._states: Dict[str, Dict[str, Any]] = {}

    def get_or_create_context(self, flow_id: str) -> Dict[str, Any]:
        """Retrieves or initializes internal state tracking context for a flow."""
        if flow_id not in self._states:
            self._states[flow_id] = {
                "syn_forward": False,
                "syn_ack_backward": False,
                "fin_forward": False,
                "fin_backward": False,
                "handshake_complete": False,
            }
        return self._states[flow_id]

    def remove_flow(self, flow_id: str) -> None:
        """Cleans up internal context when a flow is evicted from memory."""
        self._states.pop(flow_id, None)

    def update_state(
        self,
        flow: FlowRecord,
        flags: Optional[Dict[str, bool]],
        payload_len: int,
        direction: str
    ) -> str:
        """
        Updates the flow's logical TCP state based on packet control flags and direction.

        Transitions:
            1. RST flag received -> immediate transition to CLOSED/RESET.
            2. FIN flag received -> transition to CLOSING; once both sides or ACK exchange seen -> CLOSED/RESET.
            3. In NEW/HANDSHAKE:
               - SYN (FORWARD) -> NEW/HANDSHAKE
               - SYN/ACK (BACKWARD) -> NEW/HANDSHAKE
               - ACK (FORWARD, step 3) or payload -> ESTABLISHED
            4. In ESTABLISHED:
               - Data packets or pure ACKs maintain ESTABLISHED.

        Args:
            flow: The FlowRecord being updated.
            flags: Dictionary of TCP control flags (SYN, ACK, FIN, RST, etc.).
            payload_len: Length of TCP payload (0 for pure control packets).
            direction: "FORWARD" or "BACKWARD".

        Returns:
            The updated flow state string.
        """
        if flags is None or not isinstance(flags, dict):
            # If no TCP flags available, maintain current state
            return flow.state

        ctx = self.get_or_create_context(flow.flow_id)

        syn = bool(flags.get("SYN"))
        ack = bool(flags.get("ACK"))
        fin = bool(flags.get("FIN"))
        rst = bool(flags.get("RST"))

        # 1. RST Flag: Immediate termination (Mục 5.2 & Test T09)
        if rst:
            flow.state = TCPState.CLOSED_RESET
            return flow.state

        # 2. FIN Flag: Teardown initiation (Mục 5.2 & Test T09)
        if fin:
            if direction == "FORWARD":
                ctx["fin_forward"] = True
            else:
                ctx["fin_backward"] = True

            # If both directions have sent FIN, connection is fully closed
            if ctx["fin_forward"] and ctx["fin_backward"]:
                flow.state = TCPState.CLOSED_RESET
            else:
                flow.state = TCPState.CLOSING
            return flow.state

        # 3. Connection is currently in CLOSING state
        if flow.state == TCPState.CLOSING:
            # If an ACK is received acknowledging the FIN from the opposite direction
            if ack:
                if (ctx["fin_forward"] and direction == "BACKWARD") or \
                   (ctx["fin_backward"] and direction == "FORWARD") or \
                   (ctx["fin_forward"] and ctx["fin_backward"]):
                    flow.state = TCPState.CLOSED_RESET
            return flow.state

        # 4. Connection is currently in NEW/HANDSHAKE state (Test T07)
        if flow.state == TCPState.HANDSHAKE:
            if syn and not ack:
                # Step 1: Client SYN
                if direction == "FORWARD":
                    ctx["syn_forward"] = True
                flow.state = TCPState.HANDSHAKE

            elif syn and ack:
                # Step 2: Server SYN/ACK
                if direction == "BACKWARD":
                    ctx["syn_ack_backward"] = True
                flow.state = TCPState.HANDSHAKE

            elif ack and not syn:
                # Step 3: Client ACK completing 3-way handshake (even with payload_len == 0)
                if ctx["syn_forward"] or ctx["syn_ack_backward"] or payload_len > 0:
                    ctx["handshake_complete"] = True
                    flow.state = TCPState.ESTABLISHED
                else:
                    # Mid-stream pickup pure ACK
                    flow.state = TCPState.ESTABLISHED

            elif payload_len > 0:
                # Any payload data indicates connection is established
                flow.state = TCPState.ESTABLISHED

            return flow.state

        # 5. Connection is in ESTABLISHED state
        if flow.state == TCPState.ESTABLISHED:
            # Pure ACKs or payload data packets sustain ESTABLISHED state
            return flow.state

        # 6. Connection is already CLOSED/RESET
        return flow.state
