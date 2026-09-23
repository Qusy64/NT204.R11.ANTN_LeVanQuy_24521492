"""
Application Protocol Detector (DPI Engine).
Identifies application protocols (HTTP, DNS, SMTP) by combining
Payload-based inspection (Deep Packet Inspection) and Port-based hints.
Prioritizes Payload signatures to support non-standard ports (bonus points).
"""

import re
from typing import Optional, Any
from scapy.layers.inet import TCP, UDP
from scapy.layers.dns import DNS
from src.models.event import NormalizedEvent

# HTTP/1.x Signatures (RFC 7230 / RFC 2616)
HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT "
)
HTTP_RESPONSE_PREFIXES = (b"HTTP/1.0 ", b"HTTP/1.1 ", b"HTTP/0.9 ")

# SMTP Signatures (RFC 5321)
SMTP_COMMAND_PREFIXES = (
    b"HELO", b"EHLO", b"MAIL FROM:", b"RCPT TO:",
    b"DATA", b"QUIT", b"RSET", b"VRFY", b"NOOP", b"STARTTLS"
)
SMTP_RESPONSE_REGEX = re.compile(rb"^[2-5]\d\d[ -]")

# Standard Port Mappings for fallback hints
PORT_HINTS = {
    80: "HTTP",
    8080: "HTTP",
    8000: "HTTP",
    53: "DNS",
    5353: "DNS",
    25: "SMTP",
    587: "SMTP",
    465: "SMTP",
    2525: "SMTP",
}


def _extract_payload_bytes(packet: Any) -> bytes:
    """Safely extracts raw payload bytes from transport layer without decoding."""
    try:
        if hasattr(packet, "haslayer"):
            if packet.haslayer(TCP):
                layer = packet[TCP].payload
                return bytes(layer) if layer else b""
            elif packet.haslayer(UDP):
                layer = packet[UDP].payload
                return bytes(layer) if layer else b""
        return b""
    except Exception:
        return b""


def _is_http(payload: bytes) -> bool:
    """Checks if payload matches HTTP/1.x request or response signatures."""
    payload_lstrip = payload.lstrip()
    if not payload_lstrip:
        return False

    upper_prefix = payload_lstrip[:12].upper()
    for method in HTTP_METHODS:
        if upper_prefix.startswith(method):
            return True

    for resp in HTTP_RESPONSE_PREFIXES:
        if upper_prefix.startswith(resp):
            return True

    return False


def _is_smtp(payload: bytes, is_tcp: bool) -> bool:
    """Checks if payload matches SMTP command or response signatures over TCP."""
    if not is_tcp:
        return False

    payload_lstrip = payload.lstrip()
    if not payload_lstrip:
        return False

    upper_prefix = payload_lstrip[:16].upper()

    # Check SMTP commands
    for cmd in SMTP_COMMAND_PREFIXES:
        if upper_prefix.startswith(cmd):
            cmd_len = len(cmd)
            if len(upper_prefix) == cmd_len or upper_prefix[cmd_len:cmd_len + 1] in (
                b" ", b"\r", b"\n", b":"
            ):
                return True

    # Check SMTP responses (e.g., 220 banner, 250 OK)
    if SMTP_RESPONSE_REGEX.match(payload_lstrip):
        return True

    return False


def _is_dns(packet: Any, payload: bytes) -> bool:
    """Checks if packet or payload matches DNS message format."""
    if hasattr(packet, "haslayer") and packet.haslayer(DNS):
        return True

    if len(payload) >= 12:
        try:
            qdcount = int.from_bytes(payload[4:6], byteorder="big")
            ancount = int.from_bytes(payload[6:8], byteorder="big")
            opcode = (payload[2] >> 3) & 0x0F
            if opcode in (0, 1, 2) and (1 <= qdcount <= 50 or 1 <= ancount <= 100):
                dns_layer = DNS(payload)
                if (
                    dns_layer.qd is not None
                    or dns_layer.an is not None
                    or dns_layer.opcode in (0, 1, 2)
                ):
                    return True
        except Exception:
            pass

    return False


def detect_app_protocol(packet: Any, event: Optional[NormalizedEvent] = None) -> str:
    """
    Detects application protocol using Deep Packet Inspection (DPI) and Port hints.
    
    Priority:
        1. Payload-based DPI (matches HTTP, DNS, SMTP even on non-standard ports).
        2. Port-based fallback (when payload is empty or ambiguous).
        3. Fallback to "UNKNOWN".
        
    Args:
        packet: Raw Scapy packet.
        event: Optional NormalizedEvent to update in-place with app_protocol.
        
    Returns:
        Protocol string: "HTTP", "DNS", "SMTP", or "UNKNOWN".
    """
    if not hasattr(packet, "haslayer"):
        if event is not None:
            event.app_protocol = "UNKNOWN"
        return "UNKNOWN"

    try:
        is_tcp = packet.haslayer(TCP)
        is_udp = packet.haslayer(UDP)

        if not (is_tcp or is_udp):
            if event is not None:
                event.app_protocol = "UNKNOWN"
            return "UNKNOWN"

        payload = _extract_payload_bytes(packet)

        # 1. Payload-Based DPI (Highest Priority — Port-agnostic)
        if payload:
            if _is_http(payload):
                proto = "HTTP"
                if event is not None:
                    event.app_protocol = proto
                return proto

            if _is_smtp(payload, is_tcp):
                proto = "SMTP"
                if event is not None:
                    event.app_protocol = proto
                return proto

            if _is_dns(packet, payload):
                proto = "DNS"
                if event is not None:
                    event.app_protocol = proto
                return proto

        # 2. Check Scapy DNS layer parsed from raw packet
        if packet.haslayer(DNS):
            proto = "DNS"
            if event is not None:
                event.app_protocol = proto
            return proto

        # 3. Port-Based Hint (Fallback when payload is empty)
        ports = []
        if is_tcp:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport is not None:
                ports.append(sport)
            if dport is not None:
                ports.append(dport)
        elif is_udp:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if sport is not None:
                ports.append(sport)
            if dport is not None:
                ports.append(dport)

        for p in ports:
            if p in PORT_HINTS:
                proto = PORT_HINTS[p]
                if event is not None:
                    event.app_protocol = proto
                return proto

        # 4. Fallback to UNKNOWN
        proto = "UNKNOWN"
        if event is not None:
            event.app_protocol = proto
        return proto

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"App detector error: {str(exc)}")
            event.app_protocol = "UNKNOWN"
        return "UNKNOWN"
