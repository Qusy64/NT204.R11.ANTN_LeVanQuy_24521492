"""
IPv4 Network Layer Parser.
Extracts and standardizes RFC 791 IPv4 header fields into an IPv4Info dataclass.
"""

from typing import Optional, Dict, Any
from scapy.layers.inet import IP
from src.models.event import IPv4Info, NormalizedEvent

# Common IP Protocol Number to Name Mapping (RFC 790 / IANA)
PROTOCOL_MAP: Dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


def parse_ipv4(packet: Any, event: Optional[NormalizedEvent] = None) -> Optional[IPv4Info]:
    """
    Parses IPv4 network layer fields from a raw packet.
    
    Args:
        packet: Raw Scapy packet.
        event: Optional NormalizedEvent to update in-place with parsed network info or error logs.
        
    Returns:
        IPv4Info if the packet contains a valid IPv4 header, None otherwise.
    """
    if not hasattr(packet, "haslayer") or not packet.haslayer(IP):
        return None

    try:
        ip_layer = packet[IP]
        
        proto_num = int(ip_layer.proto) if ip_layer.proto is not None else 0
        proto_name = PROTOCOL_MAP.get(proto_num, f"PROTO_{proto_num}")
        
        flags_val = ip_layer.flags
        flags_str = str(flags_val) if flags_val is not None else ""
        if flags_str == "0":
            flags_str = ""

        ipv4_info = IPv4Info(
            src_ip=str(ip_layer.src) if ip_layer.src is not None else "",
            dst_ip=str(ip_layer.dst) if ip_layer.dst is not None else "",
            version=int(ip_layer.version) if ip_layer.version is not None else 4,
            ihl=int(ip_layer.ihl) if ip_layer.ihl is not None else 5,
            tos=int(ip_layer.tos) if ip_layer.tos is not None else 0,
            total_length=int(ip_layer.len) if ip_layer.len is not None else len(ip_layer),
            identification=int(ip_layer.id) if ip_layer.id is not None else 0,
            flags=flags_str,
            ttl=int(ip_layer.ttl) if ip_layer.ttl is not None else 64,
            protocol=proto_num,
            protocol_name=proto_name,
            checksum=int(ip_layer.chksum) if ip_layer.chksum is not None else 0
        )

        if event is not None:
            event.network = ipv4_info

        return ipv4_info

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"IPv4 parse error: {str(exc)}")
        return None
