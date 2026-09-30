"""
URL and Form Percent-Decoder (Mục 3 - Module Decoder).
Decodes percent-encoded URIs and application/x-www-form-urlencoded payloads
while strictly preserving the raw original strings.
"""

import urllib.parse
from typing import Optional, Tuple, Dict, Any, List


def decode_url(uri: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Decodes a percent-encoded URI string while preserving the raw original.

    Args:
        uri: Raw URI string (e.g. "/login?user=%27%20OR%201%3D1")

    Returns:
        Tuple of (raw_uri, decoded_uri).
        Example: ("/login?user=%27%20OR%201%3D1", "/login?user=' OR 1=1")
    """
    if uri is None:
        return None, None

    raw_uri = str(uri)
    try:
        # urllib.parse.unquote decodes %xx hex escapes safely
        decoded_uri = urllib.parse.unquote(raw_uri, errors="replace")
        return raw_uri, decoded_uri
    except Exception:
        # Fault-tolerance: never crash on unexpected malformed input
        return raw_uri, raw_uri


def decode_form_urlencoded(body: Optional[str]) -> Dict[str, Any]:
    """
    Parses and decodes application/x-www-form-urlencoded payload bodies.

    Args:
        body: Form-encoded string (e.g. "user=admin&pass=%27+OR+1%3D1--")

    Returns:
        Dictionary mapping field names to decoded scalar values or lists.
    """
    if not body:
        return {}

    try:
        # parse_qs parses query strings and converts '+' to spaces, %xx to chars
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True, errors="replace")
        
        # Flatten single-item lists for clean dictionary presentation
        flattened: Dict[str, Any] = {}
        for k, v in parsed.items():
            if isinstance(v, list):
                flattened[k] = v[0] if len(v) == 1 else v
            else:
                flattened[k] = v
        return flattened
    except Exception:
        return {}
