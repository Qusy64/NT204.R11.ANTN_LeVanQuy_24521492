"""
Detection Event Generator Module (Mục 4.6 & Mục 5).
Generates standardized DetectionEvent objects upon rule matches compliant with
Section 4.6 and the output specification table in Section 5 of the assignment.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from src.models.event import NormalizedEvent
from .models import SnortRule


@dataclass
class DetectionEvent:
    """
    Standardized Detection Event Data Model (Mục 5).
    Guarantees consistent JSON Lines serialization for downstream alerting and logging.
    """
    timestamp: float
    timestamp_iso: str
    sid: int
    rev: int
    msg: str
    priority: int
    classtype: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    application_protocol: str
    flow_id: str
    matched_info: str
    action: str = "alert"

    @property
    def five_tuple(self) -> str:
        """Helper property formatted as 'src_ip:src_port -> dst_ip:dst_port / proto'."""
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} / {self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        """Converts the detection event to a JSON-compatible dictionary."""
        data = asdict(self)
        data["5-tuple"] = self.five_tuple
        return data


class DetectionEventGenerator:
    """
    Generates standardized DetectionEvent objects from matching Snort rules and events.
    Strictly avoids direct stdout printing inside matching logic (Mục 4.6).
    """

    def generate(
        self,
        rule: SnortRule,
        event: NormalizedEvent,
        matched_info: str = ""
    ) -> DetectionEvent:
        """
        Constructs a fully-populated DetectionEvent.

        Args:
            rule: The matched SnortRule.
            event: The triggering NormalizedEvent.
            matched_info: Summary of matched contents/fields.

        Returns:
            DetectionEvent instance.
        """
        ts = float(event.timestamp) if event.timestamp else 0.0
        ts_iso = event.timestamp_iso
        if not ts_iso and ts > 0:
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                ts_iso = dt.isoformat()
            except Exception:
                ts_iso = ""

        src_ip = event.src_ip or "0.0.0.0"
        dst_ip = event.dst_ip or "0.0.0.0"
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0
        proto = event.transport_type or (event.network.protocol_name if event.network else "UNKNOWN")
        app_proto = event.app_protocol or "UNKNOWN"
        flow_id = event.flow_id or "UNTRACKED"

        priority = rule.priority if rule.priority is not None else 3
        classtype = rule.classtype or "unknown"
        action = rule.header.action or "alert"

        return DetectionEvent(
            timestamp=ts,
            timestamp_iso=ts_iso,
            sid=int(rule.sid or 0),
            rev=int(rule.rev or 1),
            msg=rule.msg or "",
            priority=priority,
            classtype=classtype,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto.upper(),
            application_protocol=app_proto.upper(),
            flow_id=flow_id,
            matched_info=matched_info,
            action=action
        )
