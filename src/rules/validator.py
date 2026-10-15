"""
Snort Rule Validator Module (Mục 4.2 - Rule Validator).
Validates structural and semantic invariants of parsed SnortRule objects,
classifying each rule into 'valid', 'invalid', or 'unsupported' with descriptive reasons.
"""

import ipaddress
import re
from typing import Optional, Tuple
from .models import SnortRule, RuleHeader


def _validate_ip_spec(ip_str: str) -> bool:
    """Validates if IP spec is 'any', a single IPv4 address, or a valid CIDR network."""
    clean = str(ip_str).strip()
    if clean.lower() == "any":
        return True

    # Strip negation '!' if present
    if clean.startswith("!"):
        clean = clean[1:].strip()

    # CIDR check
    if "/" in clean:
        try:
            ipaddress.IPv4Network(clean, strict=False)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False

    # Single IP check
    try:
        ipaddress.IPv4Address(clean)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def _validate_port_spec(port_str: str) -> bool:
    """Validates if port spec is 'any', a single port (0-65535), or a valid port range."""
    clean = str(port_str).strip()
    if clean.lower() == "any":
        return True

    # Strip negation '!' if present
    if clean.startswith("!"):
        clean = clean[1:].strip()

    # Port range ':max', 'min:', 'min:max'
    if ":" in clean:
        parts = clean.split(":")
        if len(parts) != 2:
            return False
        p_min_str, p_max_str = parts[0].strip(), parts[1].strip()

        p_min = 0
        p_max = 65535

        if p_min_str:
            if not p_min_str.isdigit() or not (0 <= int(p_min_str) <= 65535):
                return False
            p_min = int(p_min_str)

        if p_max_str:
            if not p_max_str.isdigit() or not (0 <= int(p_max_str) <= 65535):
                return False
            p_max = int(p_max_str)

        return p_min <= p_max

    # Single port integer
    if clean.isdigit():
        return 0 <= int(clean) <= 65535

    return False


def validate_snort_rule(rule: SnortRule) -> SnortRule:
    """
    Validates a parsed SnortRule instance against Section 3 and Section 4.2 invariants.

    Classification:
        - 'invalid': Syntax errors, missing mandatory fields (sid, msg), invalid IP/port/header.
        - 'unsupported': Contains keywords outside Section 3 scope (e.g., pcre, byte_test).
        - 'valid': All header, identification, content, and packet options fully comply with scope.

    Args:
        rule: SnortRule instance from parser.

    Returns:
        Updated SnortRule with validated status and reason.
    """
    if rule is None:
        return SnortRule(status="invalid", reason="Rule is None")

    # If parser already detected an invalid syntax or unsupported keyword
    if rule.status in ("invalid", "unsupported") and rule.reason:
        return rule

    header = rule.header

    # 1. Action validation (Mục 3: alert)
    if header.action != "alert":
        rule.status = "invalid"
        rule.reason = f"Unsupported or invalid rule action: '{header.action}' (expected 'alert')"
        return rule

    # 2. Protocol validation (Mục 3: TCP, UDP)
    if header.protocol not in ("TCP", "UDP"):
        rule.status = "invalid"
        rule.reason = f"Unsupported protocol: '{header.protocol}' (expected 'TCP' or 'UDP')"
        return rule

    # 3. Direction validation (Mục 3: ->, <>)
    if header.direction not in ("->", "<>", "<->"):
        rule.status = "invalid"
        rule.reason = f"Invalid direction operator: '{header.direction}' (expected '->' or '<>')"
        return rule

    # 4. IP specifications validation (Mục 3: any, IPv4, CIDR)
    if not _validate_ip_spec(header.src_ip):
        rule.status = "invalid"
        rule.reason = f"Invalid source IP specification: '{header.src_ip}'"
        return rule

    if not _validate_ip_spec(header.dst_ip):
        rule.status = "invalid"
        rule.reason = f"Invalid destination IP specification: '{header.dst_ip}'"
        return rule

    # 5. Port specifications validation (Mục 3: any, single, range)
    if not _validate_port_spec(header.src_port):
        rule.status = "invalid"
        rule.reason = f"Invalid source port specification: '{header.src_port}'"
        return rule

    if not _validate_port_spec(header.dst_port):
        rule.status = "invalid"
        rule.reason = f"Invalid destination port specification: '{header.dst_port}'"
        return rule

    # 6. Mandatory Rule Options (Mục 3 & Mục 4.2)
    if rule.sid is None or rule.sid <= 0:
        rule.status = "invalid"
        rule.reason = "Missing or invalid mandatory option: 'sid' must be a positive integer"
        return rule

    if not rule.msg:
        rule.status = "invalid"
        rule.reason = "Missing mandatory option: 'msg' description text"
        return rule

    # All checks passed cleanly
    rule.status = "valid"
    rule.reason = None
    return rule
