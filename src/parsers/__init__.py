"""
Parsers Package.
Contains protocol layer parsers for Network (IPv4), Transport (TCP/UDP),
Application (HTTP, DNS, SMTP), and Application Protocol Detector (DPI).
"""

from .network import parse_ipv4

__all__ = ["parse_ipv4"]
