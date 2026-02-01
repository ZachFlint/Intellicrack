"""Intellicrack launcher with full DEBUG console logging.

Convenience script that launches Intellicrack with --verbose
so all DEBUG-level log messages are printed to the console.

Usage:
    pixi run python scripts/run.py
    python scripts/run.py
"""

from __future__ import annotations

import sys

from intellicrack.main import main


if "--verbose" not in sys.argv and "-v" not in sys.argv and "--log-level" not in sys.argv:
    sys.argv.append("--verbose")

sys.exit(main())
