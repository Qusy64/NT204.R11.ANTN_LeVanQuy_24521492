"""
Snort Rules Package (Bài tập 3 - Core Engine & Snort Rule Matching).
Exports core rule data models, parser, validator, loader, indexer, matcher, generator, and engine.
"""

from .models import SnortRule, RuleHeader, ContentPattern
from .parser import parse_snort_rule
from .validator import validate_snort_rule
from .loader import (
    load_rules_from_file,
    load_rules_from_string,
    load_rules_from_directory
)
from .indexer import RuleIndexer
from .repository import RuleRepository
from .matcher import RuleMatchingEngine
from .generator import DetectionEvent, DetectionEventGenerator
from .engine import RuleEvaluationEngine

__all__ = [
    "SnortRule",
    "RuleHeader",
    "ContentPattern",
    "parse_snort_rule",
    "validate_snort_rule",
    "load_rules_from_file",
    "load_rules_from_string",
    "load_rules_from_directory",
    "RuleIndexer",
    "RuleRepository",
    "RuleMatchingEngine",
    "DetectionEvent",
    "DetectionEventGenerator",
    "RuleEvaluationEngine",
]
