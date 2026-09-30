"""
Event Normalizer (Mục 4 - Module Preprocessor).
Standardizes protocol names, IP addresses, domains, HTTP header keys, URI paths,
timestamps, and provides consistent null/[] defaults for missing fields.
"""

import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from src.models.event import NormalizedEvent, HTTPInfo, DNSInfo, SMTPInfo


def normalize_protocol_name(proto: Optional[str]) -> str:
    """Normalizes protocol name to uppercase canonical format (e.g. 'tcp' -> 'TCP')."""
    if not proto:
        return "UNKNOWN"
    return str(proto).strip().upper()


def normalize_ip(ip: Optional[str]) -> str:
    """Normalizes IP address string by trimming whitespace."""
    if not ip:
        return ""
    return str(ip).strip()


def normalize_domain(domain: Optional[str]) -> str:
    """
    Normalizes domain/hostname to lowercase stripped format (RFC 1035).
    Example: 'GOOGLE.COM. ' -> 'google.com'
    """
    if not domain:
        return ""
    cleaned = str(domain).strip().lower()
    # Strip optional trailing root dot in FQDN if present
    if cleaned.endswith(".") and len(cleaned) > 1:
        cleaned = cleaned[:-1]
    return cleaned


def normalize_http_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    Normalizes HTTP header keys to lowercase canonical format.
    Example: {'Host': 'EXAMPLE.COM', 'Content-Type': 'text/html'}
          -> {'host': 'EXAMPLE.COM', 'content-type': 'text/html'}
    """
    if not headers or not isinstance(headers, dict):
        return {}

    normalized: Dict[str, str] = {}
    for k, v in headers.items():
        if k is not None:
            norm_key = str(k).strip().lower()
            norm_val = str(v).strip() if v is not None else ""
            normalized[norm_key] = norm_val
    return normalized


def normalize_uri_path(uri: Optional[str]) -> str:
    """
    Safely normalizes URI path by removing duplicate slashes and redundant dot segments.
    Example: '//api//v1/./users?query=1' -> '/api/v1/users?query=1'
    """
    if not uri:
        return "/"

    raw = str(uri).strip()
    if not raw:
        return "/"

    # Separate path from query string/hash
    parts = raw.split("?", 1)
    path = parts[0]
    query = f"?{parts[1]}" if len(parts) > 1 else ""

    # Collapse multiple consecutive slashes
    path = re.sub(r"/{2,}", "/", path)

    # Normalize '/./' -> '/'
    path = re.sub(r"/\./", "/", path)

    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path

    return path + query


def normalize_timestamp(ts: Optional[float]) -> str:
    """Generates standard UTC ISO 8601 string from epoch timestamp."""
    if ts is None or ts <= 0:
        return ""
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.isoformat()
    except Exception:
        return ""


def normalize_event_fields(event: NormalizedEvent) -> None:
    """
    Applies comprehensive in-place normalization across all layers of NormalizedEvent.
    Guarantees consistent null/[] representation for missing optional data.
    """
    if event is None:
        return

    # 1. Timestamp Normalization
    if event.timestamp and not event.timestamp_iso:
        event.timestamp_iso = normalize_timestamp(event.timestamp)

    # 2. Network Layer Normalization
    if event.network is not None:
        event.network.src_ip = normalize_ip(event.network.src_ip)
        event.network.dst_ip = normalize_ip(event.network.dst_ip)
        event.network.protocol_name = normalize_protocol_name(event.network.protocol_name)

    # 3. Transport Layer Normalization
    if event.transport_type:
        event.transport_type = normalize_protocol_name(event.transport_type)

    # 4. Application Layer Protocol Name
    if event.app_protocol:
        event.app_protocol = normalize_protocol_name(event.app_protocol)

    # 5. Protocol-specific Normalization
    if isinstance(event.application, HTTPInfo):
        # Normalize HTTP headers
        event.application.headers = normalize_http_headers(event.application.headers)

        # Normalize URI and Host
        if event.application.uri:
            event.application.uri = normalize_uri_path(event.application.uri)
        if event.application.decoded_uri:
            event.application.decoded_uri = normalize_uri_path(event.application.decoded_uri)

        # Lowercase 'host' header value
        if "host" in event.application.headers:
            event.application.headers["host"] = normalize_domain(event.application.headers["host"])

    elif isinstance(event.application, DNSInfo):
        # Normalize queries domain
        if event.application.queries:
            for q in event.application.queries:
                if isinstance(q, dict) and "domain" in q:
                    q["domain"] = normalize_domain(q["domain"])
                if isinstance(q, dict) and "type" in q:
                    q["type"] = normalize_protocol_name(q["type"])

        # Normalize answers domain
        if event.application.answers:
            for a in event.application.answers:
                if isinstance(a, dict) and "domain" in a:
                    a["domain"] = normalize_domain(a["domain"])
                if isinstance(a, dict) and "type" in a:
                    a["type"] = normalize_protocol_name(a["type"])

    elif isinstance(event.application, SMTPInfo):
        if event.application.command:
            event.application.command = normalize_protocol_name(event.application.command)
        if event.application.arguments:
            # If arguments contain email domain or HELO domain, trim and clean
            event.application.arguments = event.application.arguments.strip()
