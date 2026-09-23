"""
DNS Protocol Parser.
Parses DNS Query and Response messages into the DNSInfo dataclass
compliant with RFC 1035 and Section 9 of the assignment.
"""

from typing import Optional, Dict, Any, List
from scapy.layers.inet import UDP, TCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from src.models.event import DNSInfo, NormalizedEvent

# Standard DNS Query / Resource Record Types (RFC 1035 / IANA)
QTYPE_MAP: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    255: "ANY",
}


def _is_valid_dns(dns: Optional[DNS]) -> bool:
    """Validates that a DNS layer has questions or answers."""
    if dns is None:
        return False
    try:
        # A valid DNS query or response must contain at least a question or answer
        has_qd = bool(dns.qd)
        has_an = bool(dns.an)
        if not has_qd and not has_an:
            return False
        return True
    except Exception:
        return False


def _extract_dns_layer(packet: Any) -> Optional[DNS]:
    """Safely extracts or parses the Scapy DNS layer from a packet."""
    dns_cand: Optional[DNS] = None

    if hasattr(packet, "haslayer") and packet.haslayer(DNS):
        dns_cand = packet[DNS]
    else:
        # Try parsing raw payload on UDP or TCP only if valid DNS structure
        try:
            if hasattr(packet, "haslayer"):
                if packet.haslayer(UDP):
                    payload = bytes(packet[UDP].payload)
                    if len(payload) >= 12:
                        dns_cand = DNS(payload)
                elif packet.haslayer(TCP):
                    payload = bytes(packet[TCP].payload)
                    if len(payload) >= 14:
                        dns_cand = DNS(payload[2:])
        except Exception:
            pass

    if _is_valid_dns(dns_cand):
        return dns_cand

    return None


def _extract_records(field_val: Any) -> List[Any]:
    """
    Safely extracts all records from a Scapy DNS section (qd, an, ns, ar),
    supporting both list representations and chained Packet payloads.
    """
    records: List[Any] = []
    if field_val is None:
        return records

    # If Scapy stored it as a list
    if isinstance(field_val, list):
        for item in field_val:
            if item is not None:
                records.append(item)
        return records

    # If Scapy stored it as a chained packet
    curr = field_val
    while curr:
        records.append(curr)
        if hasattr(curr, "payload") and curr.payload:
            curr = curr.payload
        else:
            break

    return records


def parse_dns(packet: Any, event: Optional[NormalizedEvent] = None) -> Optional[DNSInfo]:
    """
    Parses DNS Query and Response messages from a raw packet.
    
    Supports:
        - DNS Query: extracts queried domain name and query type (A, AAAA, MX, etc.)
        - DNS Response: extracts all answer resource records (name, type, TTL, resolved data)
        
    Args:
        packet: Raw Scapy packet containing DNS data.
        event: Optional NormalizedEvent to update in-place with DNSInfo.
        
    Returns:
        DNSInfo dataclass if payload is valid DNS, None otherwise.
    """
    dns = _extract_dns_layer(packet)
    if dns is None:
        return None

    try:
        transaction_id = int(dns.id) if dns.id is not None else 0
        qr = int(dns.qr) if dns.qr is not None else 0
        opcode = int(dns.opcode) if dns.opcode is not None else 0
        rcode = int(dns.rcode) if dns.rcode is not None else 0
        msg_type = "RESPONSE" if qr == 1 else "QUERY"

        # 1. Parse Queries (Question section)
        queries: List[Dict[str, str]] = []
        for r in _extract_records(dns.qd):
            qname = getattr(r, "qname", b"")
            if isinstance(qname, bytes):
                qname_str = qname.decode("utf-8", errors="replace").rstrip(".")
            else:
                qname_str = str(qname).rstrip(".")

            qtype_raw = getattr(r, "qtype", 1)
            if isinstance(qtype_raw, str):
                qtype_str = qtype_raw.upper()
            elif isinstance(qtype_raw, int):
                qtype_str = QTYPE_MAP.get(qtype_raw, str(qtype_raw))
            else:
                try:
                    qtype_str = QTYPE_MAP.get(int(qtype_raw), str(qtype_raw))
                except (ValueError, TypeError):
                    qtype_str = str(qtype_raw) if qtype_raw is not None else "A"

            queries.append({
                "domain": qname_str,
                "type": qtype_str,
            })

        # 2. Parse Answers (Resource records)
        answers: List[Dict[str, Any]] = []
        for r in _extract_records(dns.an):
            rrname = getattr(r, "rrname", b"")
            if isinstance(rrname, bytes):
                rrname_str = rrname.decode("utf-8", errors="replace").rstrip(".")
            else:
                rrname_str = str(rrname).rstrip(".")

            rrtype_raw = getattr(r, "type", 1)
            if isinstance(rrtype_raw, str):
                rrtype_str = rrtype_raw.upper()
            elif isinstance(rrtype_raw, int):
                rrtype_str = QTYPE_MAP.get(rrtype_raw, str(rrtype_raw))
            else:
                try:
                    rrtype_str = QTYPE_MAP.get(int(rrtype_raw), str(rrtype_raw))
                except (ValueError, TypeError):
                    rrtype_str = str(rrtype_raw) if rrtype_raw is not None else "A"

            rdata_raw = getattr(r, "rdata", "")
            if isinstance(rdata_raw, bytes):
                rdata_str = rdata_raw.decode("utf-8", errors="replace")
            else:
                rdata_str = str(rdata_raw)

            ttl_val = getattr(r, "ttl", 0)
            ttl_int = int(ttl_val) if ttl_val is not None else 0

            answers.append({
                "domain": rrname_str,
                "type": rrtype_str,
                "ttl": ttl_int,
                "data": rdata_str,
            })

        dns_info = DNSInfo(
            msg_type=msg_type,
            transaction_id=transaction_id,
            qr=qr,
            opcode=opcode,
            rcode=rcode,
            queries=queries,
            answers=answers,
        )

        # 3. Update event in-place
        if event is not None:
            event.app_protocol = "DNS"
            event.application = dns_info

        return dns_info

    except Exception as exc:
        if event is not None:
            event.is_malformed = True
            event.errors.append(f"DNS parse error: {str(exc)}")
        return None
