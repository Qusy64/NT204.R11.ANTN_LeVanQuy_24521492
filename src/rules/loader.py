"""
Snort Rule Loader Module (Mục 4.1 - Rule Loader).
Loads Snort rules from files or raw text, filters blank lines and comments,
provides robust zero-crash error recovery, and supports enable/disable configuration.
"""

import os
import sys
from typing import List, Optional, Set
from .models import SnortRule
from .parser import parse_snort_rule
from .validator import validate_snort_rule


def load_rules_from_string(
    content: str,
    enabled_sids: Optional[Set[int]] = None,
    disabled_sids: Optional[Set[int]] = None
) -> List[SnortRule]:
    """
    Parses and validates Snort rules from a multi-line string.
    Filters comments ('#') and blank lines compliant with Section 4.1.

    Args:
        content: Multi-line string containing Snort rules.
        enabled_sids: Optional set of SIDs to selectively enable.
        disabled_sids: Optional set of SIDs to selectively disable.

    Returns:
        List of SnortRule objects (including valid, invalid, and unsupported rules).
    """
    rules: List[SnortRule] = []
    if not content:
        return rules

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # 1. Skip blank lines and full-line comments (Mục 4.1)
        if not stripped or stripped.startswith("#"):
            continue

        # 2. Defensive boundary: Zero-crash on unexpected rule malformation
        try:
            rule = parse_snort_rule(stripped)
            rule = validate_snort_rule(rule)

            # Apply enable/disable configuration (Mục 4.1)
            if rule.sid is not None:
                if disabled_sids and rule.sid in disabled_sids:
                    rule.enabled = False
                elif enabled_sids and rule.sid not in enabled_sids:
                    rule.enabled = False

            rules.append(rule)

        except Exception as exc:
            # Fault-tolerance: single rule error never halts loading of remaining rules
            sys.stderr.write(f"[WARN] Failed to parse rule at line {line_num}: {exc}\n")
            invalid_rule = SnortRule(
                status="invalid",
                reason=f"Parser exception at line {line_num}: {str(exc)}",
                raw_text=stripped
            )
            rules.append(invalid_rule)

    return rules


def load_rules_from_file(
    filepath: str,
    enabled_sids: Optional[Set[int]] = None,
    disabled_sids: Optional[Set[int]] = None
) -> List[SnortRule]:
    """
    Loads, parses, and validates Snort rules from a .rules file (Mục 4.1).

    Args:
        filepath: Path to the .rules file on disk.
        enabled_sids: Optional set of SIDs to selectively enable.
        disabled_sids: Optional set of SIDs to selectively disable.

    Returns:
        List of SnortRule objects loaded from the file.
    """
    if not os.path.exists(filepath):
        sys.stderr.write(f"[WARN] Rules file not found: {filepath}\n")
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return load_rules_from_string(content, enabled_sids, disabled_sids)
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to read rules file '{filepath}': {exc}\n")
        return []


def load_rules_from_directory(
    dirpath: str,
    enabled_sids: Optional[Set[int]] = None,
    disabled_sids: Optional[Set[int]] = None
) -> List[SnortRule]:
    """
    Recursively scans a directory for all .rules files and loads rules from each.

    Args:
        dirpath: Directory path to scan.
        enabled_sids: Optional set of SIDs to selectively enable.
        disabled_sids: Optional set of SIDs to selectively disable.

    Returns:
        Aggregated list of all loaded SnortRule objects.
    """
    all_rules: List[SnortRule] = []
    if not os.path.isdir(dirpath):
        return all_rules

    for root, _, files in os.walk(dirpath):
        for file in sorted(files):
            if file.endswith(".rules"):
                full_path = os.path.join(root, file)
                loaded = load_rules_from_file(full_path, enabled_sids, disabled_sids)
                all_rules.extend(loaded)

    return all_rules
