"""
Preprocessor Engine (Mục 4 - Module Preprocessor).
Coordinates Validation, Normalization, Missing Data Standardization, and Metadata Tagging
to produce a clean, uniform event representation for downstream Flow Tracking and Detection.
"""

from typing import Optional, List
from src.models.event import NormalizedEvent
from .validator import validate_event
from .normalizer import normalize_event_fields


class PreprocessorEngine:
    """
    Central Preprocessor Engine orchestrating data validation and normalization.
    """

    def __init__(self, drop_invalid: bool = False):
        """
        Args:
            drop_invalid: Policy flag; if True, invalid events are tagged action 'DROP'.
                          If False, tagged 'INSPECT' for forensics inspection.
        """
        self.drop_invalid = drop_invalid

    def preprocess(self, event: NormalizedEvent) -> NormalizedEvent:
        """
        Preprocesses a NormalizedEvent in-place.

        Workflow:
            1. Validates required fields, IP formats, port ranges, timestamps.
            2. Normalizes protocol names, IP/domain cases, HTTP header names, URI paths.
            3. Tags metadata: preprocess_status, processing_action, reason.
            4. Catches all internal exceptions to guarantee zero crash.

        Args:
            event: NormalizedEvent to preprocess.

        Returns:
            NormalizedEvent enriched with preprocessing metadata and normalized fields.
        """
        if event is None:
            return event

        try:
            # 1. Validation Step (Mục 4)
            val_status, reasons = validate_event(event)
            event.validation_status = val_status
            event.preprocess_status = val_status

            # 2. Determine Processing Action & Reason
            if val_status == "invalid":
                event.processing_action = "DROP" if self.drop_invalid else "INSPECT"
                event.reason = "; ".join(reasons) if reasons else "Invalid event data"
            elif val_status == "partial":
                event.processing_action = "INSPECT"
                event.reason = "; ".join(reasons) if reasons else "Partial event data"
            else:
                event.processing_action = "FORWARD"
                event.reason = None

            # 3. Normalization Step (Mục 4)
            # Even for partial/invalid packets, normalize what is present to maintain consistency
            normalize_event_fields(event)

        except Exception as exc:
            event.preprocess_status = "invalid"
            event.processing_action = "DROP" if self.drop_invalid else "INSPECT"
            event.reason = f"Preprocessor engine error: {str(exc)}"
            event.errors.append(str(exc))

        return event
