"""
Transport Layer Parser.
Extracts and standardizes RFC 793 (TCP) and RFC 768 (UDP) transport header fields
into TCPInfo and UDPInfo dataclasses.
"""

from typing import Optional, Dict, Tuple, Any, Union
from scapy.layers.inet import TCP, UDP
from src.models.event import TCPInfo, UDPInfo, NormalizedEvent

# Standard flag bitmasks for TCP (RFC 793, RFC 3168)
TCP_FLAG_ORDER = ["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"]


def extract_tcp_flags(flags_val: Any) -> Tuple[Dict[str, bool], str]:
    """
    Extracts individual TCP flags from a Scapy FlagValue, integer bitmask, or string.
    
    Returns:
        Tuple of (flags_dict: Dict[str, bool], flag_summary: str)
    """
    flags_int = 0
    if flags_val is not None:
        try:
            flags_int = int(flags_val)
        except (ValueError, TypeError):
            flags_str = str(flags_val).upper()
            flags_dict = {
                "SYN": "S" in flags_str,
                "ACK": "A" in flags_str,
                "FIN": "F" in flags_str,
                "RST": "R" in flags_str,
                "PSH": "P" in flags_str,
                "URG": "U" in flags_str,
                "ECE": "E" in flags_str,
                "CWR": "C" in flags_str,
            }
            active = [f for f in TCP_FLAG_ORDER if flags_dict[f]]
            return flags_dict, ", ".join(active)

    flags_dict = {
        "SYN": bool(flags_int & 0x02),
        "ACK": bool(flags_int & 0x10),
        "FIN": bool(flags_int & 0x01),
        "RST": bool(flags_int & 0x04),
        "PSH": bool(flags_int & 0x08),
        "URG": bool(flags_int & 0x20),
        "ECE": bool(flags_int & 0x40),
        "CWR": bool(flags_int & 0x80),
    }
    active = [f for f in TCP_FLAG_ORDER if flags_dict[f]]
    return flags_dict, ", ".join(active)


def parse_tcp(packet: Any, event: Optional[NormalizedEvent] = None) -> Optional[TCPInfo]:
    """
    Parses TCP header fields from a raw Scapy packet.
    
    Args:
        packet: Raw Scapy packet.
        event: Optional NormalizedEvent to update in-place with parsed transport info.
        
    Returns:
        TCPInfo if packet contains a valid TCP header, None otherwise.
    """
    if not hasattr(packet, "haslayer") or not packet.haslayer(TCP):
        return None

    try:
        tcp = packet[TCP]
        flags_dict, flag_summary = extract_tcp_flags(tcp.flags)

        payload_len = 0
        if hasattr(tcp, "payload") and tcp.payload:
            try:
                payload_len = len(tcp.payload)
            except Exception:
                payload_len = 0

        tcp_info = TCPInfo(
            src_port=int(tcp.sport) if tcp.sport is not None else 0,
            dst_port=int(tcp.dport) if tcp.dport is not None else 0,
            seq=int(tcp.seq) if tcp.seq is not None else 0,
            ack=int(tcp.ack) if tcp.ack is not None else 0,
            data_offset=int(tcp.dataofs) if tcp.dataofs is not None else 5,
            flags=flags_dict,
            flag_summary=flag_summary,
            window=int(tcp.window) if tcp.window is not None else 0,
            checksum=int(tcp.chksum) if tcp.chksum is not None else 0,
            payload_len=payload_len,
        )

        if event is not None:
            event.transport_type = "TCP"
            event.transport = tcp_info
            if payload_len > 0:
                event.raw_payload_len = payload_len

        return tcp_info

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"TCP parse error: {str(exc)}")
        return None


def parse_udp(packet: Any, event: Optional[NormalizedEvent] = None) -> Optional[UDPInfo]:
    """
    Parses UDP header fields from a raw Scapy packet.
    
    Args:
        packet: Raw Scapy packet.
        event: Optional NormalizedEvent to update in-place with parsed transport info.
        
    Returns:
        UDPInfo if packet contains a valid UDP header, None otherwise.
    """
    if not hasattr(packet, "haslayer") or not packet.haslayer(UDP):
        return None

    try:
        udp = packet[UDP]

        payload_len = 0
        if hasattr(udp, "payload") and udp.payload:
            try:
                payload_len = len(udp.payload)
            except Exception:
                payload_len = 0

        # Safe fallback for UDP length when unbuilt in RAM
        udp_len = (
            int(udp.len)
            if udp.len is not None
            else (len(udp) if hasattr(udp, "__len__") else 8 + payload_len)
        )

        udp_info = UDPInfo(
            src_port=int(udp.sport) if udp.sport is not None else 0,
            dst_port=int(udp.dport) if udp.dport is not None else 0,
            length=udp_len,
            checksum=int(udp.chksum) if udp.chksum is not None else 0,
            payload_len=payload_len,
        )

        if event is not None:
            event.transport_type = "UDP"
            event.transport = udp_info
            if payload_len > 0:
                event.raw_payload_len = payload_len

        return udp_info

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"UDP parse error: {str(exc)}")
        return None


def parse_transport(
    packet: Any, event: Optional[NormalizedEvent] = None
) -> Tuple[Optional[str], Optional[Union[TCPInfo, UDPInfo]]]:
    """
    Convenience orchestrator that dispatches a packet to either TCP or UDP parser.
    
    Args:
        packet: Raw Scapy packet.
        event: Optional NormalizedEvent to update in-place.
        
    Returns:
        Tuple of (transport_type: "TCP" | "UDP" | None, transport_info: TCPInfo | UDPInfo | None)
    """
    if not hasattr(packet, "haslayer"):
        return None, None

    if packet.haslayer(TCP):
        tcp_info = parse_tcp(packet, event)
        return ("TCP", tcp_info) if tcp_info else (None, None)
    elif packet.haslayer(UDP):
        udp_info = parse_udp(packet, event)
        return ("UDP", udp_info) if udp_info else (None, None)
    else:
        return None, None
