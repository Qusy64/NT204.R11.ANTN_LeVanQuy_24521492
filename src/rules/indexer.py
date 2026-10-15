"""
Rule Indexer Module (Mục 4.3 - Rule Repository / Indexer).
Provides multi-dimensional indexing (protocol, destination port, IP) to rapidly select
candidate rules for incoming packets, avoiding expensive full rule-table scans.
"""

from typing import List, Dict, Set, Optional, Tuple
from .models import SnortRule


def _parse_port_range(port_spec: str) -> Tuple[int, int]:
    """Parses a port range string into (min_port, max_port)."""
    clean = port_spec.strip()
    if clean.startswith("!"):
        clean = clean[1:].strip()

    if ":" in clean:
        parts = clean.split(":")
        p_min = int(parts[0].strip()) if parts[0].strip() else 0
        p_max = int(parts[1].strip()) if parts[1].strip() else 65535
        return p_min, p_max

    if clean.isdigit():
        p = int(clean)
        return p, p

    return 0, 65535


class RuleIndexer:
    """
    Multi-level indexer organizing validated rules by:
        1. Protocol: TCP, UDP, ANY
        2. Destination Port: Exact single port, Port range, or ANY
    """

    def __init__(self):
        # Protocol -> exact destination port -> list of rules
        self._exact_dport: Dict[str, Dict[int, List[SnortRule]]] = {
            "TCP": {}, "UDP": {}, "ANY": {}
        }
        # Protocol -> list of (min_port, max_port, rule)
        self._range_dport: Dict[str, List[Tuple[int, int, SnortRule]]] = {
            "TCP": [], "UDP": [], "ANY": []
        }
        # Protocol -> list of rules targeting 'any' destination port
        self._any_dport: Dict[str, List[SnortRule]] = {
            "TCP": [], "UDP": [], "ANY": []
        }
        # All indexed rules list
        self._all_indexed_rules: List[SnortRule] = []

    def index_rule(self, rule: SnortRule) -> None:
        """
        Indexes a single validated and enabled SnortRule.
        """
        if not rule.is_valid or not rule.enabled:
            return

        proto = rule.header.protocol.upper()
        if proto not in ("TCP", "UDP"):
            proto = "ANY"

        dst_port_spec = rule.header.dst_port.strip().lower()

        # 1. Any destination port
        if dst_port_spec == "any":
            self._any_dport[proto].append(rule)

        # 2. Port range (contains ':')
        elif ":" in dst_port_spec:
            p_min, p_max = _parse_port_range(dst_port_spec)
            self._range_dport[proto].append((p_min, p_max, rule))

        # 3. Exact single port
        elif dst_port_spec.isdigit():
            port_num = int(dst_port_spec)
            if port_num not in self._exact_dport[proto]:
                self._exact_dport[proto][port_num] = []
            self._exact_dport[proto][port_num].append(rule)

        else:
            # Fallback for complex port specs
            self._any_dport[proto].append(rule)

        self._all_indexed_rules.append(rule)

    def get_candidate_rules(
        self,
        protocol: str,
        dst_port: Optional[int] = None
    ) -> List[SnortRule]:
        """
        Retrieves the filtered subset of candidate rules compatible with the packet header.

        Args:
            protocol: Packet transport protocol ('TCP', 'UDP', or other).
            dst_port: Packet destination port integer.

        Returns:
            Deduplicated list of candidate SnortRules.
        """
        proto_clean = str(protocol).strip().upper() if protocol else "ANY"
        applicable_protos = [proto_clean]
        if "ANY" not in applicable_protos:
            applicable_protos.append("ANY")

        candidates: List[SnortRule] = []
        seen_sids: Set[int] = set()

        for p in applicable_protos:
            if p not in self._any_dport:
                continue

            # 1. Add rules with any destination port
            for rule in self._any_dport[p]:
                if rule.sid not in seen_sids:
                    seen_sids.add(rule.sid)
                    candidates.append(rule)

            if dst_port is not None:
                # 2. Add exact port matches
                exact_list = self._exact_dport[p].get(int(dst_port), [])
                for rule in exact_list:
                    if rule.sid not in seen_sids:
                        seen_sids.add(rule.sid)
                        candidates.append(rule)

                # 3. Add range port matches
                for p_min, p_max, rule in self._range_dport[p]:
                    if p_min <= int(dst_port) <= p_max:
                        if rule.sid not in seen_sids:
                            seen_sids.add(rule.sid)
                            candidates.append(rule)

        return candidates

    def clear(self) -> None:
        """Clears all indexed rules."""
        self.__init__()
