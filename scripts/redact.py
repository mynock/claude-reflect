#!/usr/bin/env python3
"""Print stdin with API keys, tokens, passwords and private keys redacted.

Cross-platform compatible (Windows, macOS, Linux).
/reflect runs each entry through this before writing it to a memory file.

Usage: printf '%s\\n' "entry text" | python3 redact.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.reflect_utils import ensure_utf8_io, redact_secrets


def main() -> int:
    ensure_utf8_io()
    sys.stdout.write(redact_secrets(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
