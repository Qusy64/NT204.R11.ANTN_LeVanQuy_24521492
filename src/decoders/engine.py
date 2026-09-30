"""
Decoder Engine (Mục 3 - Module Decoder).
Integrates URL, HTML entity, MIME Base64/Quoted-Printable, and Character decoders
to enrich NormalizedEvent instances while maintaining 100% zero-crash resilience.
"""

import re
from typing import Optional, Any
from src.models.event import NormalizedEvent, HTTPInfo, SMTPInfo
from .url_decoder import decode_url, decode_form_urlencoded
from .html_decoder import decode_html_entities
from .mime_decoder import decode_mime
from .character_decoder import decode_character_safe


class DecoderEngine:
    """
    Central decoder engine applying required representations decoders
    according to application protocol and payload characteristics.
    """

    def decode(self, event: NormalizedEvent) -> NormalizedEvent:
        """
        Enriches a NormalizedEvent with decoded representations.

        Args:
            event: NormalizedEvent from packet parser.

        Returns:
            NormalizedEvent with decoded fields populated.
        """
        if event is None:
            return event

        try:
            # 1. HTTP Decoding (Mục 3: URL, Form, HTML Entity)
            if event.app_protocol == "HTTP" and isinstance(event.application, HTTPInfo):
                self._decode_http(event.application, event)

            # 2. SMTP / MIME Decoding (Mục 3: Base64, Quoted-Printable)
            elif event.app_protocol == "SMTP" and isinstance(event.application, SMTPInfo):
                self._decode_smtp(event.application, event)

            # 3. Fallback character decoding for non-HTTP/SMTP or unparsed payloads
            else:
                self._decode_generic_payload(event)

        except Exception as exc:
            event.decode_status = "FAILED"
            event.errors.append(f"Decoder engine error: {str(exc)}")

        return event

    def _decode_http(self, http_info: HTTPInfo, event: NormalizedEvent) -> None:
        """Applies URL percent-decoding, form decoding, and HTML entity decoding to HTTP."""
        # 1. URI Percent-Decoding (Preserve raw_uri, compute decoded_uri)
        if http_info.uri:
            raw_uri, decoded_uri = decode_url(http_info.uri)
            http_info.raw_uri = raw_uri
            http_info.decoded_uri = decoded_uri
        
        # 2. Form URL-Encoded Body
        content_type = ""
        for k, v in http_info.headers.items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break

        if "application/x-www-form-urlencoded" in content_type and http_info.body:
            http_info.decoded_params = decode_form_urlencoded(http_info.body)

        # 3. HTML Entity Decoding on Body
        if http_info.body:
            decoded_html, html_status = decode_html_entities(http_info.body)
            http_info.decoded_body = decoded_html
            if html_status == "SUCCESS":
                http_info.decode_status = "SUCCESS"
            else:
                http_info.decode_status = "NONE"

            # Check character validity of body
            _, char_status = decode_character_safe(http_info.body)
            if char_status == "PARTIAL":
                http_info.decode_status = "PARTIAL"
                event.decode_status = "PARTIAL"
                event.errors.append("Invalid byte sequence in HTTP body")

    def _decode_smtp(self, smtp_info: SMTPInfo, event: NormalizedEvent) -> None:
        """Applies Base64 and Quoted-Printable MIME decoding to SMTP email body."""
        # Determine encoding header
        encoding_header = smtp_info.content_transfer_encoding
        if not encoding_header:
            for k, v in smtp_info.headers.items():
                if k.lower() == "content-transfer-encoding":
                    encoding_header = v.strip()
                    smtp_info.content_transfer_encoding = encoding_header
                    break

        body_candidate = smtp_info.body or smtp_info.arguments or smtp_info.message

        # If MIME header was inside body_candidate (common in raw email streams)
        if body_candidate and not encoding_header:
            header_match = re.search(r"Content-Transfer-Encoding:\s*([a-zA-Z0-9\-_]+)", body_candidate, re.IGNORECASE)
            if header_match:
                encoding_header = header_match.group(1).strip()
                smtp_info.content_transfer_encoding = encoding_header
                # Extract actual body after double CRLF if present
                if "\r\n\r\n" in body_candidate:
                    body_candidate = body_candidate.split("\r\n\r\n", 1)[1]
                elif "\n\n" in body_candidate:
                    body_candidate = body_candidate.split("\n\n", 1)[1]

        if body_candidate:
            decoded_body, decode_status = decode_mime(body_candidate, encoding_header)
            smtp_info.decoded_body = decoded_body
            smtp_info.decode_status = decode_status
            event.decode_status = decode_status
        else:
            smtp_info.decode_status = "NONE"

    def _decode_generic_payload(self, event: NormalizedEvent) -> None:
        """Inspects generic or unparsed payloads for character validity."""
        if event.decoded_payload is not None:
            _, char_status = decode_character_safe(event.decoded_payload)
            if char_status == "PARTIAL":
                event.decode_status = "PARTIAL"
                event.errors.append("Invalid byte sequence in payload")
            else:
                event.decode_status = "VALID"
