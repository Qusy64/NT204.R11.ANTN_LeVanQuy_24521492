"""
SMTP Protocol Parser.
Parses SMTP Command and Response messages into the SMTPInfo dataclass
compliant with RFC 5321 and Section 9 of the assignment.
"""

import re
from typing import Optional, Any
from scapy.layers.inet import TCP
from src.models.event import SMTPInfo, NormalizedEvent

# Response regex: matches 3-digit reply code (200-599) followed by space, hyphen, or end of line
# e.g., "220 mail.example.com ESMTP", "250-mail.example.com", "250 OK"
SMTP_RESPONSE_PATTERN = re.compile(r"^([2-5]\d{2})(?:[ -]|\r?\n|$)", re.MULTILINE)

# Standard single-word commands (RFC 5321)
SMTP_STANDARD_COMMANDS = {
    "HELO", "EHLO", "DATA", "QUIT", "RSET",
    "VRFY", "EXPN", "NOOP", "STARTTLS", "AUTH", "HELP", "BDAT"
}


def _extract_tcp_payload(packet: Any) -> Optional[bytes]:
    """Safely extracts raw byte payload from a TCP packet or bytes object."""
    if hasattr(packet, "haslayer") and packet.haslayer(TCP):
        try:
            payload = bytes(packet[TCP].payload)
            if payload:
                return payload
        except Exception:
            return None
    elif isinstance(packet, (bytes, bytearray)):
        if packet:
            return bytes(packet)
    return None


def parse_smtp(packet: Any, event: Optional[NormalizedEvent] = None) -> Optional[SMTPInfo]:
    """
    Parses SMTP Command and Response messages from a TCP packet or raw payload.

    Supports:
        - SMTP Command: extracts command name (HELO, EHLO, MAIL FROM, RCPT TO, DATA, QUIT, etc.)
          and any accompanying arguments (domains, email addresses, etc.).
        - SMTP Response: extracts 3-digit status code (220, 250, 354, 550, etc.)
          and accompanying message text.

    Args:
        packet: Scapy TCP packet or raw bytes containing SMTP data.
        event: Optional NormalizedEvent to update in-place with SMTPInfo.

    Returns:
        SMTPInfo dataclass if payload is valid SMTP, None otherwise.
    """
    payload = _extract_tcp_payload(packet)
    if not payload:
        return None

    try:
        # Decode text safely without crashing on binary or malformed bytes
        text = payload.decode("utf-8", errors="replace").strip()
        if not text:
            return None

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return None

        first_line = lines[0]
        first_line_upper = first_line.upper()

        # 1. Check for SMTP Response (e.g., "220 ...", "250 ...")
        resp_match = SMTP_RESPONSE_PATTERN.match(first_line)
        if resp_match:
            status_code = int(resp_match.group(1))
            
            # Extract message text: if single-line or multi-line, collect message contents
            # Clean off leading status code and separators from lines
            msg_parts = []
            for line in lines:
                m = re.match(r"^[2-5]\d{2}[ -]?(.*)$", line)
                if m:
                    msg_parts.append(m.group(1).strip())
                else:
                    msg_parts.append(line)
            message_text = " ".join([p for p in msg_parts if p]).strip()

            smtp_info = SMTPInfo(
                msg_type="RESPONSE",
                command=None,
                arguments=None,
                status_code=status_code,
                message=message_text,
            )

            if event is not None:
                event.app_protocol = "SMTP"
                event.application = smtp_info

            return smtp_info

        # 2. Check for Multi-word SMTP Commands: MAIL FROM: / RCPT TO:
        if first_line_upper.startswith("MAIL FROM"):
            after_cmd = first_line[len("MAIL FROM"):]
            arguments = after_cmd.lstrip(": ").strip()
            smtp_info = SMTPInfo(
                msg_type="COMMAND",
                command="MAIL FROM",
                arguments=arguments if arguments else None,
                status_code=None,
                message=None,
            )
            if event is not None:
                event.app_protocol = "SMTP"
                event.application = smtp_info
            return smtp_info

        if first_line_upper.startswith("RCPT TO"):
            after_cmd = first_line[len("RCPT TO"):]
            arguments = after_cmd.lstrip(": ").strip()
            smtp_info = SMTPInfo(
                msg_type="COMMAND",
                command="RCPT TO",
                arguments=arguments if arguments else None,
                status_code=None,
                message=None,
            )
            if event is not None:
                event.app_protocol = "SMTP"
                event.application = smtp_info
            return smtp_info

        # 3. Check for Single-word SMTP Commands (HELO, EHLO, DATA, QUIT, etc.)
        tokens = first_line.split(None, 1)
        cmd_candidate = tokens[0].upper()
        if cmd_candidate in SMTP_STANDARD_COMMANDS:
            arguments = tokens[1].strip() if len(tokens) > 1 else None
            smtp_info = SMTPInfo(
                msg_type="COMMAND",
                command=cmd_candidate,
                arguments=arguments if arguments else None,
                status_code=None,
                message=None,
            )
            if event is not None:
                event.app_protocol = "SMTP"
                event.application = smtp_info
            return smtp_info

        # If payload does not match any valid SMTP signature, return None safely
        return None

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"SMTP parse error: {str(exc)}")
        return None
