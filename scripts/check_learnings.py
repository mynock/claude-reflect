#!/usr/bin/env python3
"""Backup queue before context compaction. PreCompact hook.

Cross-platform compatible (Windows, macOS, Linux).
This script is called by Claude Code's PreCompact hook to back up
the learnings queue before context is compacted.
"""
import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.reflect_utils import (
    get_backup_dir,
    load_queue,
    backup_timestamp,
    ensure_utf8_io,
    redact_queue_items,
)


def main() -> int:
    """Main entry point."""
    ensure_utf8_io()
    items = load_queue()
    if not items:
        return 0

    # Create backup directory if needed
    backup_dir = get_backup_dir()
    backup_dir.mkdir(parents=True, exist_ok=True)

    # Save backup with timestamp. Written from the parsed items rather than a
    # raw copy so that a queue saved before redaction existed is redacted too.
    backup_file = backup_dir / f"pre-compact-{backup_timestamp()}.json"
    backup_file.write_text(
        json.dumps(redact_queue_items(items), indent=2),
        encoding="utf-8",
    )

    # Output informational message (non-blocking)
    print()
    print(f"Note: {len(items)} learning(s) backed up to {backup_file}")
    print("Run /reflect in new session to process.")
    print()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Never block on errors - just log and exit 0
        print(f"Warning: check_learnings.py error: {e}", file=sys.stderr)
        sys.exit(0)
