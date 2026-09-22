"""
Normalized IDS Event Data Models.
Standardized data structures for packets parsed by the ingestion pipeline.
These models ensure downstream Detection Engines (Snort-like rules, Anomaly Detection)
never directly touch raw Scapy/PyShark packets.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Union


@dataclass
class IPv4Info:
    """Represents standardized IPv4 network layer fields."""
    src_ip: str
    dst_ip: str
    version: int = 4
    ihl: int = 5
    tos: int = 0
    total_length: int = 0
    identification: int = 0
    flags: str = ""
    ttl: int = 64
    protocol: int = 0             # 6 for TCP, 17 for UDP
    protocol_name: str = "UNKNOWN"
    checksum: int = 0


@dataclass
class TCPInfo:
    """Represents standardized TCP transport layer fields."""
    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    data_offset: int = 0
    flags: Dict[str, bool] = field(default_factory=lambda: {
        "SYN": False, "ACK": False, "FIN": False,
        "RST": False, "PSH": False, "URG": False,
        "ECE": False, "CWR": False
    })
    flag_summary: str = ""        # e.g. "SYN, ACK"
    window: int = 0
    checksum: int = 0
    payload_len: int = 0


@dataclass
class UDPInfo:
    """Represents standardized UDP transport layer fields."""
    src_port: int
    dst_port: int
    length: int = 0
    checksum: int = 0
    payload_len: int = 0


@dataclass
class HTTPInfo:
    """Represents standardized HTTP/1.x application layer fields."""
    msg_type: str = "UNKNOWN"     # "REQUEST" | "RESPONSE"
    method: Optional[str] = None  # GET, POST, etc.
    uri: Optional[str] = None
    version: Optional[str] = None # HTTP/1.1, HTTP/1.0
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_len: int = 0


@dataclass
class DNSInfo:
    """Represents standardized DNS application layer fields."""
    msg_type: str = "UNKNOWN"     # "QUERY" | "RESPONSE"
    transaction_id: int = 0
    qr: int = 0                   # 0 for query, 1 for response
    opcode: int = 0
    rcode: int = 0
    queries: List[Dict[str, str]] = field(default_factory=list)
    answers: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SMTPInfo:
    """Represents standardized SMTP application layer fields."""
    msg_type: str = "UNKNOWN"     # "COMMAND" | "RESPONSE"
    command: Optional[str] = None # HELO, EHLO, MAIL FROM, RCPT TO, DATA, QUIT
    arguments: Optional[str] = None
    status_code: Optional[int] = None
    message: Optional[str] = None


@dataclass
class NormalizedEvent:
    """
    Unified, standardized IDS Event structure.
    This is the core data contract passed to logging (.jsonl) and downstream detection engines.
    """
    packet_id: int
    timestamp: float
    timestamp_iso: str = ""
    
    # Layer 3: Network
    network: Optional[IPv4Info] = None
    
    # Layer 4: Transport
    transport_type: Optional[str] = None   # "TCP" | "UDP" | None
    transport: Optional[Union[TCPInfo, UDPInfo]] = None
    
    # Layer 7: Application
    app_protocol: str = "UNKNOWN"          # "HTTP" | "DNS" | "SMTP" | "UNKNOWN"
    application: Optional[Union[HTTPInfo, DNSInfo, SMTPInfo]] = None
    
    # Metadata & Fault Tolerance
    raw_payload_len: int = 0
    is_malformed: bool = False
    errors: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp_iso and self.timestamp:
            dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
            self.timestamp_iso = dt.isoformat()

    @property
    def src_ip(self) -> Optional[str]:
        return self.network.src_ip if self.network else None

    @property
    def dst_ip(self) -> Optional[str]:
        return self.network.dst_ip if self.network else None

    @property
    def src_port(self) -> Optional[int]:
        if self.transport:
            return self.transport.src_port
        return None

    @property
    def dst_port(self) -> Optional[int]:
        if self.transport:
            return self.transport.dst_port
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event dataclass into a JSON-compatible dictionary."""
        data = asdict(self)
        
        # Flatten top-level convenience fields for easy consumption in JSON Lines
        data["src_ip"] = self.src_ip
        data["dst_ip"] = self.dst_ip
        data["src_port"] = self.src_port
        data["dst_port"] = self.dst_port
        
        return data
