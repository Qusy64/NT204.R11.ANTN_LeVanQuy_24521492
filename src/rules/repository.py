"""
Rule Repository Module (Mục 4.3 - Rule Repository / Indexer).
Manages storage, lifecycle, indexing, and lookup of all parsed and validated Snort rules.
"""

from typing import Dict, List, Optional, Set
from .models import SnortRule
from .indexer import RuleIndexer
from .loader import load_rules_from_file, load_rules_from_directory


class RuleRepository:
    """
    Central storage and index manager for all rules in the Core Engine.
    Separates valid, invalid, and unsupported rules to ensure zero-crash resilience.
    """

    def __init__(self):
        self.indexer = RuleIndexer()
        self.valid_rules: Dict[int, SnortRule] = {}       # sid -> SnortRule
        self.invalid_rules: List[SnortRule] = []
        self.unsupported_rules: List[SnortRule] = []

    def register_rule(self, rule: SnortRule) -> None:
        """
        Registers a single rule into the repository and indexer according to its status.
        """
        if rule is None:
            return

        if rule.status == "valid":
            if rule.sid is not None:
                self.valid_rules[rule.sid] = rule
            if rule.enabled:
                self.indexer.index_rule(rule)

        elif rule.status == "invalid":
            self.invalid_rules.append(rule)

        elif rule.status == "unsupported":
            self.unsupported_rules.append(rule)

    def register_rules(self, rules: List[SnortRule]) -> None:
        """Registers a batch of rules."""
        for rule in rules:
            self.register_rule(rule)

    def load_from_file(
        self,
        filepath: str,
        enabled_sids: Optional[Set[int]] = None,
        disabled_sids: Optional[Set[int]] = None
    ) -> int:
        """Loads and indexes rules from a .rules file. Returns count of valid rules loaded."""
        loaded = load_rules_from_file(filepath, enabled_sids, disabled_sids)
        self.register_rules(loaded)
        return len([r for r in loaded if r.is_valid])

    def load_from_directory(
        self,
        dirpath: str,
        enabled_sids: Optional[Set[int]] = None,
        disabled_sids: Optional[Set[int]] = None
    ) -> int:
        """Loads and indexes all rules from a directory. Returns count of valid rules loaded."""
        loaded = load_rules_from_directory(dirpath, enabled_sids, disabled_sids)
        self.register_rules(loaded)
        return len([r for r in loaded if r.is_valid])

    def get_candidate_rules(
        self,
        protocol: str,
        dst_port: Optional[int] = None
    ) -> List[SnortRule]:
        """
        Queries the indexer to return only relevant candidate rules for the packet header.
        """
        return self.indexer.get_candidate_rules(protocol, dst_port)

    def get_rule_by_sid(self, sid: int) -> Optional[SnortRule]:
        """Looks up a valid rule by its SID."""
        return self.valid_rules.get(int(sid))

    @property
    def total_rules(self) -> int:
        return len(self.valid_rules) + len(self.invalid_rules) + len(self.unsupported_rules)

    @property
    def valid_count(self) -> int:
        return len(self.valid_rules)

    @property
    def invalid_count(self) -> int:
        return len(self.invalid_rules)

    @property
    def unsupported_count(self) -> int:
        return len(self.unsupported_rules)

    def summary(self) -> Dict[str, int]:
        return {
            "total": self.total_rules,
            "valid": self.valid_count,
            "invalid": self.invalid_count,
            "unsupported": self.unsupported_count,
        }

    def clear(self) -> None:
        """Resets the repository and indexer."""
        self.indexer.clear()
        self.valid_rules.clear()
        self.invalid_rules.clear()
        self.unsupported_rules.clear()
