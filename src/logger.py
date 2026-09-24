"""
JSON Lines Logging Module.
Serializes NormalizedEvent objects into newline-delimited JSON format (.jsonl)
compliant with Section 8 of the assignment.
"""

import json
import os
from typing import Optional, Any, TextIO
from src.models.event import NormalizedEvent


class JsonLinesLogger:
    """
    Stream writer that outputs NormalizedEvent instances into a JSON Lines (.jsonl) file.
    Ensures immediate buffer flushing for real-time observability and crash resilience.
    """

    def __init__(self, filepath: str, mode: str = "w"):
        """
        Initializes the logger and creates parent directories if needed.

        Args:
            filepath: Destination file path for the .jsonl output.
            mode: File open mode ("w" for overwrite, "a" for append).
        """
        self.filepath = filepath
        self.mode = mode
        self.file_handle: Optional[TextIO] = None
        self.events_logged: int = 0

        # Create destination directory structure if absent
        parent_dir = os.path.dirname(filepath)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        self._open()

    def _open(self) -> None:
        """Opens the file handle with UTF-8 encoding."""
        if self.file_handle is None or self.file_handle.closed:
            self.file_handle = open(self.filepath, mode=self.mode, encoding="utf-8")

    def log_event(self, event: NormalizedEvent) -> None:
        """
        Serializes a single NormalizedEvent and writes it as one JSON line.

        Args:
            event: Fully populated NormalizedEvent dataclass.
        """
        if self.file_handle is None or self.file_handle.closed:
            self._open()

        data_dict = event.to_dict()
        line = json.dumps(data_dict, ensure_ascii=False)
        self.file_handle.write(line + "\n")
        self.file_handle.flush()
        self.events_logged += 1

    def close(self) -> None:
        """Flushes and closes the underlying file handle."""
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.flush()
            self.file_handle.close()

    def __enter__(self) -> "JsonLinesLogger":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
