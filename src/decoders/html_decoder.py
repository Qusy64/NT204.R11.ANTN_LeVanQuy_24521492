"""
HTML Entity Decoder (Mục 3 - Module Decoder).
Decodes HTML entities (e.g. &lt;script&gt; -> <script>) in payload text
compliant with W3C / HTML5 entity specifications.
"""

import html
from typing import Optional, Tuple


def decode_html_entities(text: Optional[str]) -> Tuple[Optional[str], str]:
    """
    Decodes HTML entities in a text string to their canonical characters.

    Args:
        text: Text string potentially containing HTML entities
              (e.g., "&lt;script&gt;alert(1)&lt;/script&gt;")

    Returns:
        Tuple of (decoded_text, decode_status).
        Status is "SUCCESS" if entities were decoded, "NO_OP" if no entities existed,
        or "FAILED" if decoding failed.
    """
    if text is None:
        return None, "NO_OP"

    raw_text = str(text)
    try:
        decoded_text = html.unescape(raw_text)
        if decoded_text != raw_text:
            return decoded_text, "SUCCESS"
        return raw_text, "NO_OP"
    except Exception:
        # Fault-tolerance: never crash on unexpected input
        return raw_text, "FAILED"
