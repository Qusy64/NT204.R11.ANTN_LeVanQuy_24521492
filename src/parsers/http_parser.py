"""
HTTP/1.x Protocol Parser.
Parses HTTP/1.x Request and Response messages into the HTTPInfo dataclass
compliant with RFC 7230 / RFC 2616.
"""

from typing import Optional, Dict, Any
from scapy.layers.inet import TCP
from src.models.event import HTTPInfo, NormalizedEvent

# Standard HTTP/1.x Request Methods
HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "OPTIONS", "PATCH", "TRACE", "CONNECT"
}


def _extract_payload_bytes(packet: Any) -> bytes:
    """Safely extracts raw payload bytes from the TCP layer."""
    if hasattr(packet, "haslayer") and packet.haslayer(TCP):
        layer = packet[TCP].payload
        return bytes(layer) if layer else b""
    if hasattr(packet, "load"):
        return bytes(packet.load)
    return b""


def parse_http(packet: Any, event: Optional[NormalizedEvent] = None) -> Optional[HTTPInfo]:
    """
    Parses an HTTP/1.x message from a raw packet.
    
    Supports:
        - HTTP Request (GET, POST with body, PUT, DELETE, etc.)
        - HTTP Response (Status code, reason phrase, response headers)
        
    Args:
        packet: Raw Scapy packet containing TCP payload.
        event: Optional NormalizedEvent to update in-place with HTTPInfo.
        
    Returns:
        HTTPInfo dataclass if payload is valid HTTP, None otherwise.
    """
    payload = _extract_payload_bytes(packet)
    if not payload:
        return None

    try:
        # 1. Split header and body at delimiter (\r\n\r\n or \n\n)
        if b"\r\n\r\n" in payload:
            header_bytes, body_bytes = payload.split(b"\r\n\r\n", 1)
        elif b"\n\n" in payload:
            header_bytes, body_bytes = payload.split(b"\n\n", 1)
        else:
            header_bytes = payload
            body_bytes = b""

        # 2. Decode header safely (errors='replace' prevents UnicodeDecodeError)
        header_text = header_bytes.decode("utf-8", errors="replace")
        lines = header_text.splitlines()
        if not lines:
            return None

        # Filter out empty leading lines if any
        non_empty_lines = [line.strip() for line in lines if line.strip()]
        if not non_empty_lines:
            return None

        start_line = non_empty_lines[0]
        parts = start_line.split(" ")

        msg_type = "UNKNOWN"
        method: Optional[str] = None
        uri: Optional[str] = None
        version: Optional[str] = None
        status_code: Optional[int] = None
        reason_phrase: Optional[str] = None

        # 3. Determine if Request or Response
        first_token = parts[0].upper()
        if first_token in HTTP_METHODS or (len(parts) >= 2 and parts[-1].upper().startswith("HTTP/")):
            # HTTP Request
            msg_type = "REQUEST"
            method = first_token
            uri = parts[1] if len(parts) > 1 else "/"
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        elif first_token.startswith("HTTP/"):
            # HTTP Response
            msg_type = "RESPONSE"
            version = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                status_code = int(parts[1])
            if len(parts) > 2:
                reason_phrase = " ".join(parts[2:])

        else:
            # Not a recognized HTTP start line
            return None

        # 4. Parse Headers into a dictionary
        headers: Dict[str, str] = {}
        for line in non_empty_lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()

        # 5. Parse Body and calculate byte length
        body_len = len(body_bytes)
        body_str: Optional[str] = None
        if body_bytes:
            body_str = body_bytes.decode("utf-8", errors="replace")

        http_info = HTTPInfo(
            msg_type=msg_type,
            method=method,
            uri=uri,
            version=version,
            status_code=status_code,
            reason_phrase=reason_phrase,
            headers=headers,
            body=body_str,
            body_len=body_len,
        )

        # 6. Update event in-place
        if event is not None:
            event.app_protocol = "HTTP"
            event.application = http_info
            if body_len > 0 and event.raw_payload_len == 0:
                event.raw_payload_len = body_len

        return http_info

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"HTTP parse error: {str(exc)}")
        return None
