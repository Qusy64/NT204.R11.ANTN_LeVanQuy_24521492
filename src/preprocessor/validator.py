"""
Event Validator (Mục 4 - Module Preprocessor).
Validates required fields, IPv4 address formats, port ranges (0-65535),
protocol numbers, and timestamps. Assigns validation status (valid/partial/invalid).
"""

import ipaddress
from typing import Tuple, List, Optional
from src.models.event import NormalizedEvent


def validate_ip(ip_str: Optional[str]) -> bool:
    """Checks if a string is a valid IPv4 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_event(event: NormalizedEvent) -> Tuple[str, List[str]]:
    """
    Validates a NormalizedEvent against structural and semantic invariants.

    Validation rules:
        - Mandatory: packet_id, timestamp > 0, network layer.
        - Network: src_ip and dst_ip must be valid IPv4 addresses, protocol >= 0.
        - Transport: If present, src_port and dst_port must be in range [0, 65535].
        - Classification:
            * "invalid": Missing mandatory network/IP fields, invalid IP, or out-of-range ports.
            * "partial": Basic IP/transport are valid, but event was flagged malformed, or missing optional fields.
            * "valid": All mandatory and present fields comply with strict standards.

    Args:
        event: NormalizedEvent to validate.

    Returns:
        Tuple of (validation_status: str, reasons: List[str]).
    """
    reasons: List[str] = []

    if event is None:
        return "invalid", ["Event is None"]

    # 1. Check timestamp
    if event.timestamp is None or event.timestamp <= 0:
        reasons.append("Invalid or missing timestamp")

    # 2. Check network layer
    if event.network is None:
        reasons.append("Missing network layer (IPv4)")
    else:
        if not validate_ip(event.network.src_ip):
            reasons.append(f"Invalid src_ip: '{event.network.src_ip}'")
        if not validate_ip(event.network.dst_ip):
            reasons.append(f"Invalid dst_ip: '{event.network.dst_ip}'")
        if event.network.protocol is None or event.network.protocol < 0:
            reasons.append(f"Invalid IP protocol number: {event.network.protocol}")

    # 3. Check transport layer ports
    if event.transport is not None:
        sport = event.transport.src_port
        dport = event.transport.dst_port

        if sport is None or not (0 <= sport <= 65535):
            reasons.append(f"src_port out of range [0, 65535]: {sport}")
        if dport is None or not (0 <= dport <= 65535):
            reasons.append(f"dst_port out of range [0, 65535]: {dport}")

    # 4. Determine overall validation status
    # Critical violations lead to "invalid"
    critical_errors = [
        r for r in reasons
        if "src_ip" in r or "dst_ip" in r or "out of range" in r or "Missing network" in r or "timestamp" in r
    ]

    if critical_errors:
        return "invalid", reasons

    if event.is_malformed or len(event.errors) > 0 or reasons:
        return "partial", reasons + event.errors

    return "valid", []
