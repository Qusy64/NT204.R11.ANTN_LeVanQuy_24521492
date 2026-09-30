"""
Character Decoder (Mục 3 - Module Decoder).
Ensures safe ASCII and UTF-8 string decoding from arbitrary binary payloads.
Provides zero-crash fallback with 'replace' and tags invalid byte sequences as PARTIAL/INVALID.
"""

from typing import Tuple, Union, Optional


def decode_character_safe(
    raw_payload: Optional[Union[bytes, bytearray, str]],
    encoding: str = "utf-8"
) -> Tuple[str, str]:
    """
    Safely decodes raw byte sequence to text using ASCII/UTF-8.

    Args:
        raw_payload: Binary data or string to decode.
        encoding: Target encoding (default: 'utf-8').

    Returns:
        Tuple of (decoded_text, decode_status).
        decode_status can be:
            - "VALID": Cleanly decoded without errors.
            - "PARTIAL": Contains replacement characters (\ufffd) due to invalid byte sequences.
            - "EMPTY": Payload is empty or None.
    """
    if raw_payload is None:
        return "", "EMPTY"

    if isinstance(raw_payload, str):
        # If already decoded, inspect whether it has Unicode replacement chars
        if "\ufffd" in raw_payload:
            return raw_payload, "PARTIAL"
        return raw_payload, "VALID"

    try:
        # 1. Attempt strict decode first to verify validity
        decoded_text = bytes(raw_payload).decode(encoding, errors="strict")
        return decoded_text, "VALID"
    except (UnicodeDecodeError, ValueError):
        # 2. On invalid byte sequence, fallback to safe replacement mode
        decoded_text = bytes(raw_payload).decode(encoding, errors="replace")
        return decoded_text, "PARTIAL"
    except Exception:
        # Extreme fallback
        return str(raw_payload), "PARTIAL"
