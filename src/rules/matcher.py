"""
Rule Matching Engine Module (Mục 4.4 - Rule Matching Engine).
Evaluates whether a candidate SnortRule matches a NormalizedEvent and Flow Context.
Supports Header (IP, CIDR, Port, Direction), Flow (to_server/client, established),
Content pattern matching (nocase, offset, depth, distance, within), TCP Flags, and dsize.
"""

import ipaddress
import re
from typing import Tuple, Optional, List, Dict, Any, Union
from src.models.event import NormalizedEvent, HTTPInfo, DNSInfo, SMTPInfo
from .models import SnortRule, ContentPattern


def _match_ip(packet_ip: Optional[str], rule_ip_spec: str) -> bool:
    """Matches a packet IP address against a rule IP specification."""
    if not rule_ip_spec or rule_ip_spec.lower() == "any":
        return True

    if not packet_ip:
        return False

    spec = rule_ip_spec.strip()
    is_negated = spec.startswith("!")
    if is_negated:
        spec = spec[1:].strip()

    matched = False
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            addr = ipaddress.ip_address(packet_ip)
            matched = addr in net
        except ValueError:
            matched = False
    else:
        matched = (packet_ip.strip() == spec)

    return not matched if is_negated else matched


def _match_port(packet_port: Optional[int], rule_port_spec: str) -> bool:
    """Matches a packet port against a rule port specification."""
    if not rule_port_spec or rule_port_spec.lower() == "any":
        return True

    if packet_port is None:
        return False

    spec = rule_port_spec.strip()
    is_negated = spec.startswith("!")
    if is_negated:
        spec = spec[1:].strip()

    matched = False
    if ":" in spec:
        parts = spec.split(":")
        p_min = int(parts[0].strip()) if parts[0].strip() else 0
        p_max = int(parts[1].strip()) if parts[1].strip() else 65535
        matched = (p_min <= packet_port <= p_max)
    elif spec.isdigit():
        matched = (packet_port == int(spec))
    else:
        matched = False

    return not matched if is_negated else matched


def _match_dsize(payload_len: int, dsize_spec: str) -> bool:
    """Matches packet payload length against a dsize rule specification."""
    clean = dsize_spec.strip()
    if not clean:
        return True

    # Range: min<>max
    if "<>" in clean:
        parts = clean.split("<>")
        if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
            min_v = int(parts[0].strip())
            max_v = int(parts[1].strip())
            return min_v < payload_len < max_v
        return False

    # Comparison operators
    if clean.startswith(">="):
        val = clean[2:].strip()
        return payload_len >= int(val) if val.isdigit() else False
    elif clean.startswith("<="):
        val = clean[2:].strip()
        return payload_len <= int(val) if val.isdigit() else False
    elif clean.startswith(">"):
        val = clean[1:].strip()
        return payload_len > int(val) if val.isdigit() else False
    elif clean.startswith("<"):
        val = clean[1:].strip()
        return payload_len < int(val) if val.isdigit() else False
    elif clean.startswith("="):
        val = clean[1:].strip()
        return payload_len == int(val) if val.isdigit() else False
    elif clean.startswith("!"):
        val = clean[1:].strip()
        return payload_len != int(val) if val.isdigit() else False
    elif clean.isdigit():
        return payload_len == int(clean)

    return False


def _extract_payload_buffers(event: NormalizedEvent) -> List[Tuple[str, bytes]]:
    """Collect payload and application fields as independent search buffers.

    Keep the transport payload first to preserve existing byte offsets. Application
    fields remain searchable even when that payload is present. Never concatenate
    representations: a content chain must match entirely inside one buffer.
    """
    buffers: List[Tuple[str, bytes]] = []
    seen: set[bytes] = set()

    def add_buffer(name: str, text: Optional[str]) -> None:
        if not isinstance(text, str) or not text:
            return
        # Preserve the byte encoding already used by content patterns and payloads.
        data = text.encode("latin-1", errors="replace")
        if data not in seen:
            seen.add(data)
            buffers.append((name, data))

    add_buffer("payload", event.decoded_payload)

    application = event.application
    if isinstance(application, HTTPInfo):
        add_buffer("http.uri", application.uri)
        add_buffer("http.decoded_uri", application.decoded_uri)
        add_buffer("http.body", application.body)
        add_buffer("http.decoded_body", application.decoded_body)
    elif isinstance(application, DNSInfo):
        for query in application.queries or []:
            if isinstance(query, dict):
                add_buffer("dns.query.domain", query.get("domain"))
        for answer in application.answers or []:
            if isinstance(answer, dict):
                add_buffer("dns.answer.domain", answer.get("domain"))
    elif isinstance(application, SMTPInfo):
        add_buffer("smtp.command", application.command)
        add_buffer("smtp.arguments", application.arguments)
        add_buffer("smtp.body", application.body)
        add_buffer("smtp.decoded_body", application.decoded_body)

    return buffers


def _match_content_patterns(
    contents: List[ContentPattern], search_buf: bytes
) -> Optional[List[str]]:
    """Match the whole content chain in one buffer, with buffer-local offsets."""
    matched_details: List[str] = []
    last_match_end = 0

    for i, cp in enumerate(contents):
        target = search_buf
        pattern_bytes = cp.pattern

        if cp.nocase:
            target = target.lower()
            pattern_bytes = pattern_bytes.lower()

        buf_len = len(target)

        # Absolute offset or distance from the previous match in this buffer.
        if i == 0 or cp.distance is None:
            start_pos = cp.offset if cp.offset is not None else 0
        else:
            start_pos = last_match_end + cp.distance

        if i == 0 or cp.within is None:
            if cp.depth is not None:
                end_pos = (cp.offset or 0) + cp.depth
            else:
                end_pos = buf_len
        else:
            end_pos = last_match_end + cp.within

        start_pos = max(0, start_pos)
        end_pos = min(buf_len, end_pos)

        if start_pos > buf_len or start_pos >= end_pos:
            return None

        found_idx = target.find(pattern_bytes, start_pos, end_pos)
        if found_idx == -1:
            return None

        if cp.within is not None and (found_idx + len(pattern_bytes)) > (last_match_end + cp.within):
            return None

        last_match_end = found_idx + len(pattern_bytes)
        matched_details.append(f"content='{cp.raw_pattern}' at byte {found_idx}")

    return matched_details


class RuleMatchingEngine:
    """
    Core Evaluation Matcher executing Section 4.4 verification checks.
    """

    def match(self, rule: SnortRule, event: NormalizedEvent) -> Tuple[bool, Optional[str]]:
        """
        Evaluates if a SnortRule matches the given NormalizedEvent and Flow Context.

        Args:
            rule: Validated candidate SnortRule.
            event: NormalizedEvent with flow attributes populated.

        Returns:
            Tuple of (is_match: bool, matched_info: Optional[str]).
        """
        if not rule.is_valid or not rule.enabled:
            return False, None

        # -------------------------------------------------------------
        # 1. Header Matching (Protocol, Direction, IP, Port) - Mục 4.4
        # -------------------------------------------------------------
        header = rule.header
        pkt_proto = event.transport_type or (event.network.protocol_name if event.network else "UNKNOWN")

        if header.protocol != "ANY" and header.protocol != pkt_proto.upper():
            return False, None

        pkt_src_ip = event.src_ip
        pkt_dst_ip = event.dst_ip
        pkt_src_port = event.src_port
        pkt_dst_port = event.dst_port

        direction = header.direction
        is_bidirectional = direction in ("<>", "<->")

        # Forward match (rule_src -> rule_dst)
        fwd_match = (
            _match_ip(pkt_src_ip, header.src_ip) and
            _match_port(pkt_src_port, header.src_port) and
            _match_ip(pkt_dst_ip, header.dst_ip) and
            _match_port(pkt_dst_port, header.dst_port)
        )

        # Reverse match (rule_dst -> rule_src) if bidirectional
        rev_match = False
        if is_bidirectional:
            rev_match = (
                _match_ip(pkt_src_ip, header.dst_ip) and
                _match_port(pkt_src_port, header.dst_port) and
                _match_ip(pkt_dst_ip, header.src_ip) and
                _match_port(pkt_dst_port, header.src_port)
            )

        if not (fwd_match or rev_match):
            return False, None

        # -------------------------------------------------------------
        # 2. Flow State & Direction Matching - Mục 4.4
        # -------------------------------------------------------------
        if rule.flow:
            flow_dir = event.flow_direction or "FORWARD"
            flow_st = event.flow_state or "NEW/HANDSHAKE"

            for f_cond in rule.flow:
                cond = f_cond.lower()
                if cond in ("to_server", "from_client"):
                    if flow_dir != "FORWARD":
                        return False, None
                elif cond in ("to_client", "from_server"):
                    if flow_dir != "BACKWARD":
                        return False, None
                elif cond == "established":
                    if flow_st not in ("ESTABLISHED", "ACTIVE"):
                        return False, None
                elif cond == "not_established":
                    if flow_st in ("ESTABLISHED", "ACTIVE"):
                        return False, None

        # -------------------------------------------------------------
        # 3. Packet & Transport Matching (TCP Flags & dsize) - Mục 4.4
        # -------------------------------------------------------------
        # TCP Flags Matching
        if rule.flags:
            if not event.transport or not hasattr(event.transport, "flags") or not event.transport.flags:
                return False, None

            pkt_flags = event.transport.flags  # Dict[str, bool]
            flag_map = {
                "S": "SYN", "A": "ACK", "F": "FIN", "R": "RST",
                "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"
            }
            for req_flag in rule.flags:
                flag_name = flag_map.get(req_flag.upper())
                if flag_name and not pkt_flags.get(flag_name, False):
                    return False, None

        # dsize Matching
        if rule.dsize:
            actual_dsize = event.raw_payload_len or 0
            if not _match_dsize(actual_dsize, rule.dsize):
                return False, None

        # -------------------------------------------------------------
        # 4. Payload Content Pattern Matching - Mục 4.4
        # -------------------------------------------------------------
        matched_details: List[str] = []
        if rule.contents:
            for buffer_name, search_buf in _extract_payload_buffers(event):
                details = _match_content_patterns(rule.contents, search_buf)
                if details is not None:
                    matched_details = details
                    if buffer_name != "payload":
                        matched_details.insert(0, f"buffer='{buffer_name}'")
                    break
            else:
                return False, None

        # Summary of match information
        info_str = f"sid={rule.sid}; msg=\"{rule.msg}\""
        if matched_details:
            info_str += f"; {', '.join(matched_details)}"

        return True, info_str
