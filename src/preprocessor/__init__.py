"""
Preprocessor Package (Mục 4 - Module Preprocessor).
Provides event validation, data normalization, missing data handling, and metadata tagging.
"""

from .validator import validate_event, validate_ip
from .normalizer import (
    normalize_protocol_name,
    normalize_ip,
    normalize_domain,
    normalize_http_headers,
    normalize_uri_path,
    normalize_timestamp,
    normalize_event_fields,
)
from .engine import PreprocessorEngine

__all__ = [
    "PreprocessorEngine",
    "validate_event",
    "validate_ip",
    "normalize_protocol_name",
    "normalize_ip",
    "normalize_domain",
    "normalize_http_headers",
    "normalize_uri_path",
    "normalize_timestamp",
    "normalize_event_fields",
]
