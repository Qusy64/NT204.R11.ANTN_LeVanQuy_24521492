"""
Data Models for Snort Rules & Options (Mục 3, 4.2 & 4.6).
Defines Internal Rule Object representation including Header, Options, ContentPattern,
and rule validation status compliant with Section 3 and Section 4.2 of the assignment.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class ContentPattern:
    """
    Encapsulates a payload search pattern and its associated modifiers (Mục 3 & Mục 4.4).
    Supports nocase, absolute boundaries (offset, depth) and relative boundaries (distance, within).
    """
    pattern: bytes
    raw_pattern: str = ""
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.raw_pattern or self.pattern.decode("utf-8", errors="replace"),
            "nocase": self.nocase,
            "offset": self.offset,
            "depth": self.depth,
            "distance": self.distance,
            "within": self.within,
        }


@dataclass
class RuleHeader:
    """
    Standardized Snort Rule Header (Mục 3 & Mục 4.2).
    Format: action protocol src_ip src_port direction dst_ip dst_port
    """
    action: str = "alert"         # alert
    protocol: str = "TCP"         # TCP, UDP
    src_ip: str = "any"           # any, single IPv4, CIDR
    src_port: str = "any"         # any, single port, port range
    direction: str = "->"         # ->, <>
    dst_ip: str = "any"
    dst_port: str = "any"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnortRule:
    """
    Internal Rule Object (Mục 4.2).
    Unified structured representation of a parsed and validated Snort rule.
    """
    header: RuleHeader = field(default_factory=RuleHeader)
    msg: Optional[str] = None
    sid: Optional[int] = None
    rev: int = 1
    
    # Payload & Packet Options (Mục 3)
    contents: List[ContentPattern] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    dsize: Optional[str] = None
    flow: List[str] = field(default_factory=list)
    
    # Metadata & Classification (Mục 3)
    classtype: Optional[str] = None
    priority: Optional[int] = None
    
    # Validation & Lifecycle
    status: str = "valid"         # "valid" | "invalid" | "unsupported"
    reason: Optional[str] = None
    raw_text: str = ""
    enabled: bool = True

    @property
    def is_valid(self) -> bool:
        return self.status == "valid"

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "sid": self.sid,
            "rev": self.rev,
            "msg": self.msg,
            "status": self.status,
            "reason": self.reason,
            "enabled": self.enabled,
            "header": self.header.to_dict(),
            "contents": [c.to_dict() for c in self.contents],
            "flags": self.flags,
            "dsize": self.dsize,
            "flow": self.flow,
            "classtype": self.classtype,
            "priority": self.priority,
            "raw_text": self.raw_text,
        }
        return data
