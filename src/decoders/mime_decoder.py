"""
SMTP/MIME Decoder (Mục 3 - Module Decoder).
Decodes MIME payloads encoded with Base64 (RFC 2045) or Quoted-Printable (RFC 2045)
when indicated by Content-Transfer-Encoding headers.
"""

import base64
import quopri
import re
from typing import Optional, Tuple, Union


def decode_mime(
    body: Optional[Union[str, bytes]],
    encoding_header: Optional[str] = None
) -> Tuple[Optional[str], str]:
    """
    Decodes MIME body according to Content-Transfer-Encoding.

    Supported encodings:
        - "base64": Decodes Base64 encoded payload to UTF-8 text.
        - "quoted-printable" (or "qp"): Decodes quoted-printable entities (e.g. "=3D" -> "=").
        - "7bit", "8bit", "binary": Plaintext passthrough.

    Args:
        body: Raw encoded body (string or bytes).
        encoding_header: Content-Transfer-Encoding header value (e.g. "base64", "quoted-printable").

    Returns:
        Tuple of (decoded_body, decode_status).
        decode_status can be: "SUCCESS", "FAILED", "PARTIAL", or "NONE".
    """
    if body is None:
        return None, "NONE"

    # Convert to string and bytes representations
    if isinstance(body, bytes):
        raw_bytes = body
        raw_str = raw_bytes.decode("utf-8", errors="replace")
    else:
        raw_str = str(body)
        raw_bytes = raw_str.encode("utf-8", errors="replace")

    if not encoding_header:
        # Detect if raw_str looks unmistakably like Base64 (fallback heuristic)
        return raw_str, "NONE"

    norm_encoding = encoding_header.strip().lower()

    # 1. Base64 Decoding
    if "base64" in norm_encoding:
        try:
            # Strip whitespace and line breaks common in MIME Base64 streams
            clean_b64 = re.sub(r"\s+", "", raw_str)
            if not clean_b64:
                return "", "SUCCESS"

            # Auto-repair missing padding ('=')
            missing_padding = len(clean_b64) % 4
            if missing_padding:
                clean_b64 += "=" * (4 - missing_padding)

            decoded_bytes = base64.b64decode(clean_b64.encode("ascii", errors="replace"), validate=False)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            return decoded_text, "SUCCESS"
        except Exception:
            return raw_str, "FAILED"

    # 2. Quoted-Printable Decoding
    elif "quoted-printable" in norm_encoding or "qp" == norm_encoding:
        try:
            decoded_bytes = quopri.decodestring(raw_bytes)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            return decoded_text, "SUCCESS"
        except Exception:
            return raw_str, "FAILED"

    # 3. Plaintext passthroughs (7bit, 8bit, binary)
    elif norm_encoding in ("7bit", "8bit", "binary"):
        return raw_str, "NONE"

    # Unsupported or unknown encoding
    return raw_str, "NONE"
