"""
Snort Rule Parser Module (Mục 4.2 - Rule Parser).
Parses raw Snort rule syntax into internal SnortRule and ContentPattern structures
compliant with RFC / Snort syntax specifications and Section 3 of the assignment.
"""

import re
from typing import List, Tuple, Optional, Dict, Any
from .models import SnortRule, RuleHeader, ContentPattern

# Allowed keywords within project scope (Mục 3)
SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev", "content", "nocase",
    "offset", "depth", "distance", "within",
    "flags", "dsize", "flow", "classtype", "priority"
}


def _tokenize_options(options_str: str) -> List[str]:
    """
    Safely splits rule options string by semicolon ';'
    while respecting double quotes (e.g. msg:"text; with; semicolons").
    """
    tokens: List[str] = []
    current: List[str] = []
    in_quote = False
    escape = False

    for ch in options_str:
        if ch == '\\' and not escape:
            escape = True
            current.append(ch)
            continue

        if ch == '"' and not escape:
            in_quote = not in_quote
            current.append(ch)
        elif ch == ';' and not in_quote:
            part = "".join(current).strip()
            if part:
                tokens.append(part)
            current = []
        else:
            current.append(ch)

        escape = False

    trailing = "".join(current).strip()
    if trailing:
        tokens.append(trailing)

    return tokens


def _decode_snort_content_bytes(content_val: str) -> bytes:
    """
    Decodes Snort content string containing raw text and optional hex escapes
    (e.g., "|90 90 90|", "GET |20| /index.html").
    """
    result = bytearray()
    parts = re.split(r"\|([^|]+)\|", content_val)
    is_hex = False

    for part in parts:
        if not part:
            is_hex = not is_hex
            continue
        if is_hex:
            # Hex bytes separated by whitespace
            clean_hex = re.sub(r"\s+", "", part)
            try:
                result.extend(bytes.fromhex(clean_hex))
            except ValueError:
                # Fallback to ascii representation on malformed hex
                result.extend(part.encode("latin-1", errors="replace"))
        else:
            result.extend(part.encode("latin-1", errors="replace"))
        is_hex = not is_hex

    return bytes(result)


def parse_snort_rule(rule_text: str) -> SnortRule:
    """
    Parses a single Snort rule string into a SnortRule object.
    
    Args:
        rule_text: Single line rule string (e.g. 'alert tcp any any -> any 80 (msg:"Attack"; sid:100;)')

    Returns:
        Populated SnortRule instance (status may be 'valid', 'invalid', or 'unsupported').
    """
    clean_text = rule_text.strip()
    rule = SnortRule(raw_text=clean_text)

    if not clean_text:
        rule.status = "invalid"
        rule.reason = "Empty rule text"
        return rule

    # 1. Split Header and Options at first '(' and last ')'
    if "(" not in clean_text or not clean_text.endswith(")"):
        rule.status = "invalid"
        rule.reason = "Missing rule options enclosure '(...)'"
        return rule

    header_part = clean_text[:clean_text.find("(")].strip()
    options_part = clean_text[clean_text.find("(") + 1:-1].strip()

    # 2. Parse Rule Header (7 mandatory tokens)
    header_tokens = header_part.split()
    if len(header_tokens) != 7:
        rule.status = "invalid"
        rule.reason = f"Header requires exactly 7 tokens (found {len(header_tokens)}): '{header_part}'"
        return rule

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = header_tokens
    rule.header = RuleHeader(
        action=action.lower(),
        protocol=protocol.upper(),
        src_ip=src_ip,
        src_port=src_port,
        direction=direction,
        dst_ip=dst_ip,
        dst_port=dst_port
    )

    # 3. Parse Rule Options
    option_tokens = _tokenize_options(options_part)
    last_content: Optional[ContentPattern] = None

    for token in option_tokens:
        if ":" in token:
            opt_name, opt_val = token.split(":", 1)
            opt_name = opt_name.strip()
            opt_val = opt_val.strip()
        else:
            opt_name = token.strip()
            opt_val = ""

        # Remove surrounding quotes from option values
        clean_val = opt_val
        if clean_val.startswith('"') and clean_val.endswith('"') and len(clean_val) >= 2:
            clean_val = clean_val[1:-1]

        lower_name = opt_name.lower()

        # Check for unsupported keyword (Mục 3)
        if lower_name not in SUPPORTED_KEYWORDS:
            rule.status = "unsupported"
            rule.reason = f"Unsupported keyword: '{opt_name}'"
            # Keep parsing other tokens for completeness

        # Parse identification
        if lower_name == "msg":
            rule.msg = clean_val

        elif lower_name == "sid":
            try:
                rule.sid = int(clean_val)
            except ValueError:
                rule.status = "invalid"
                rule.reason = f"Invalid sid: '{clean_val}' (must be integer)"

        elif lower_name == "rev":
            try:
                rule.rev = int(clean_val)
            except ValueError:
                rule.rev = 1

        # Parse classification
        elif lower_name == "classtype":
            rule.classtype = clean_val

        elif lower_name == "priority":
            try:
                rule.priority = int(clean_val)
            except ValueError:
                rule.priority = 3

        # Parse flow
        elif lower_name == "flow":
            flow_items = [item.strip().lower() for item in clean_val.split(",") if item.strip()]
            rule.flow.extend(flow_items)

        # Parse packet flags
        elif lower_name == "flags":
            # Supports formats like 'flags:S', 'flags:SA', 'flags:F,A'
            clean_flags = clean_val.replace(",", "").replace(" ", "").upper()
            rule.flags = [flag_ch for flag_ch in clean_flags if flag_ch in "FSRPAUEC12"]

        # Parse payload size (dsize)
        elif lower_name == "dsize":
            rule.dsize = clean_val

        # Parse content pattern
        elif lower_name == "content":
            content_bytes = _decode_snort_content_bytes(clean_val)
            pattern = ContentPattern(
                pattern=content_bytes,
                raw_pattern=clean_val,
                nocase=False
            )
            rule.contents.append(pattern)
            last_content = pattern

        # Content modifiers
        elif lower_name == "nocase":
            if last_content is not None:
                last_content.nocase = True
            else:
                rule.status = "invalid"
                rule.reason = "'nocase' specified without preceding 'content'"

        elif lower_name == "offset":
            try:
                if last_content is not None:
                    last_content.offset = int(clean_val)
                else:
                    rule.status = "invalid"
                    rule.reason = "'offset' specified without preceding 'content'"
            except ValueError:
                rule.status = "invalid"
                rule.reason = f"Invalid offset value: '{clean_val}'"

        elif lower_name == "depth":
            try:
                if last_content is not None:
                    last_content.depth = int(clean_val)
                else:
                    rule.status = "invalid"
                    rule.reason = "'depth' specified without preceding 'content'"
            except ValueError:
                rule.status = "invalid"
                rule.reason = f"Invalid depth value: '{clean_val}'"

        elif lower_name == "distance":
            try:
                if last_content is not None:
                    last_content.distance = int(clean_val)
                else:
                    rule.status = "invalid"
                    rule.reason = "'distance' specified without preceding 'content'"
            except ValueError:
                rule.status = "invalid"
                rule.reason = f"Invalid distance value: '{clean_val}'"

        elif lower_name == "within":
            try:
                if last_content is not None:
                    last_content.within = int(clean_val)
                else:
                    rule.status = "invalid"
                    rule.reason = "'within' specified without preceding 'content'"
            except ValueError:
                rule.status = "invalid"
                rule.reason = f"Invalid within value: '{clean_val}'"

    return rule
