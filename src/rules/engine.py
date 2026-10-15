"""
Rule Evaluation Engine Module (Mục 4.5 - Rule Evaluation Engine).
Orchestrates the evaluation of NormalizedEvents against SnortRules stored in RuleRepository,
utilizing RuleMatchingEngine and DetectionEventGenerator.
Supports multi-match (all matching rules generate alerts) and tracks evaluation metrics.
"""

from typing import List, Dict, Optional, Any
from src.models.event import NormalizedEvent
from .models import SnortRule
from .repository import RuleRepository
from .matcher import RuleMatchingEngine
from .generator import DetectionEvent, DetectionEventGenerator


class RuleEvaluationEngine:
    """
    Core IDS Engine orchestrating packet/event inspection against active rule signatures.
    Coordinates RuleRepository (candidates), RuleMatchingEngine (inspection),
    and DetectionEventGenerator (alert generation).
    """

    def __init__(
        self,
        repository: Optional[RuleRepository] = None,
        matcher: Optional[RuleMatchingEngine] = None,
        generator: Optional[DetectionEventGenerator] = None,
    ):
        self.repository = repository if repository is not None else RuleRepository()
        self.matcher = matcher if matcher is not None else RuleMatchingEngine()
        self.generator = generator if generator is not None else DetectionEventGenerator()

        # Evaluation metrics (Mục 4.5)
        self.events_evaluated: int = 0
        self.candidate_rules_checked: int = 0
        self.matches_count: int = 0
        self.alerts_generated: int = 0

    def evaluate_event(self, event: NormalizedEvent) -> List[DetectionEvent]:
        """
        Evaluates a single NormalizedEvent against indexed candidate rules.
        Supports multi-matching: does not stop on first match (Mục 4.5).

        Args:
            event: NormalizedEvent with network, transport, app, and flow context.

        Returns:
            List of generated DetectionEvents (empty if no rules matched).
        """
        if event is None:
            return []

        self.events_evaluated += 1

        # Extract protocol and ports for indexing candidate selection
        proto = event.transport_type or (event.network.protocol_name if event.network else "ANY")
        candidates = self.repository.get_candidate_rules(proto, event.dst_port)

        # Also retrieve bidirectional candidate rules matching src_port if distinct
        if event.src_port is not None and event.src_port != event.dst_port:
            src_candidates = self.repository.get_candidate_rules(proto, event.src_port)
            seen_sids = {r.sid for r in candidates if r.sid is not None}
            for r in src_candidates:
                if r.header.direction in ("<>", "<->") and r.sid not in seen_sids:
                    seen_sids.add(r.sid)
                    candidates.append(r)

        matched_events: List[DetectionEvent] = []

        for rule in candidates:
            self.candidate_rules_checked += 1
            is_match, matched_info = self.matcher.match(rule, event)
            if is_match:
                self.matches_count += 1
                det_event = self.generator.generate(rule, event, matched_info or "")
                matched_events.append(det_event)
                self.alerts_generated += 1

        return matched_events

    def evaluate_events(self, events: List[NormalizedEvent]) -> List[DetectionEvent]:
        """
        Evaluates a sequence/batch of NormalizedEvents.

        Args:
            events: List of NormalizedEvent instances.

        Returns:
            Aggregated list of all generated DetectionEvents.
        """
        all_alerts: List[DetectionEvent] = []
        for event in events:
            alerts = self.evaluate_event(event)
            all_alerts.extend(alerts)
        return all_alerts

    def get_metrics(self) -> Dict[str, int]:
        """Returns the current evaluation metrics dictionary."""
        return {
            "events_evaluated": self.events_evaluated,
            "candidate_rules_checked": self.candidate_rules_checked,
            "matches_count": self.matches_count,
            "alerts_generated": self.alerts_generated,
        }

    def reset_metrics(self) -> None:
        """Resets all metrics counters to zero."""
        self.events_evaluated = 0
        self.candidate_rules_checked = 0
        self.matches_count = 0
        self.alerts_generated = 0
