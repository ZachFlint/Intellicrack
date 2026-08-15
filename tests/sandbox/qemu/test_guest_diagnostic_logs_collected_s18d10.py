# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""S18-D10: every diagnostic file the guest writes must be fetched off the guest.

The Windows collectors each write a ``.lifecycle.``/``.diag.``/``.errors.`` file
beside their data log. Those files are the only record of *why* a collector that
started produced no rows - a provider it could not enable, a parser that came
back null, a handler that threw. While a name is missing from the QEMU backend's
fetch list the file is written inside the guest and then destroyed with the
instance's temporary tree, so an empty tab is indistinguishable from a collector
that never pumped a single event.

Both gates derive their expectation from the producers themselves - the guest
monitor scripts under ``sandbox/scripts`` and the agent scripts embedded in
``qemu.py`` - rather than restating a list, so a collector that starts writing a
new diagnostic file reddens this immediately.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from intellicrack.sandbox.qemu import COLLECTOR_DIAGNOSTIC_LOG_NAMES


_SANDBOX_PACKAGE: Final[Path] = Path(__file__).resolve().parents[3] / "src" / "intellicrack" / "sandbox"
_SCRIPTS_DIR: Final[Path] = _SANDBOX_PACKAGE / "scripts"
_QEMU_MODULE: Final[Path] = _SANDBOX_PACKAGE / "qemu.py"

# The three ways a guest-side script names a log file it writes: the PowerShell
# monitors use Join-Path with an explicit -ChildPath, the PowerShell agent
# embedded in qemu.py uses Join-Path positionally, and the Python agent embedded
# in qemu.py divides a Path.
_LOG_NAME_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"-ChildPath\s+'(?P<name>[A-Za-z0-9_.]+\.log)'"),
    re.compile(r"Join-Path\s+\$logDir\s+'(?P<name>[A-Za-z0-9_.]+\.log)'"),
    re.compile(r"LOG_DIR\s*/\s*\"(?P<name>[A-Za-z0-9_.]+\.log)\""),
)

# A guest log is a diagnostic rather than a data log when its name carries one of
# these infixes. Every collector that writes one uses the same convention.
_DIAGNOSTIC_INFIXES: Final[tuple[str, ...]] = (".lifecycle.", ".diag.", ".errors.", "_errors.")


def _producer_sources() -> dict[str, str]:
    """Read every file that spells out a log name a guest script writes.

    Returns:
        dict[str, str]: Source file name mapped to its text.
    """
    sources = {path.name: path.read_text(encoding="utf-8") for path in sorted(_SCRIPTS_DIR.glob("*.ps1"))}
    sources[_QEMU_MODULE.name] = _QEMU_MODULE.read_text(encoding="utf-8")
    return sources


def _guest_log_names() -> dict[str, str]:
    """Collect every log file name a guest-side script writes.

    Returns:
        dict[str, str]: Log file name mapped to the producer that writes it.
    """
    produced: dict[str, str] = {}
    for producer, text in _producer_sources().items():
        for pattern in _LOG_NAME_PATTERNS:
            for match in pattern.finditer(text):
                produced.setdefault(match.group("name"), producer)
    return produced


def _diagnostic_log_names() -> dict[str, str]:
    """Restrict the produced log names to the diagnostic files.

    Returns:
        dict[str, str]: Diagnostic log file name mapped to its producer.
    """
    return {name: producer for name, producer in _guest_log_names().items() if any(infix in name for infix in _DIAGNOSTIC_INFIXES)}


class TestEveryGuestDiagnosticLogIsFetched:
    """The QEMU backend's fetch list must cover the guest's diagnostic files."""

    def test_the_producers_are_actually_found(self) -> None:
        """A derivation that matched nothing would make both gates vacuous."""
        produced = _guest_log_names()
        assert len(produced) > 10, f"the log-name derivation found only {sorted(produced)}; the patterns no longer match the guest scripts"
        diagnostics = _diagnostic_log_names()
        assert len(diagnostics) > 4, f"only {sorted(diagnostics)} classified as diagnostics; the naming convention changed"

    def test_no_diagnostic_log_is_left_inside_the_guest(self) -> None:
        """Every diagnostic file a guest script writes is fetched off the guest."""
        collected = set(COLLECTOR_DIAGNOSTIC_LOG_NAMES)
        stranded = {name: producer for name, producer in _diagnostic_log_names().items() if name not in collected}
        assert not stranded, (
            "these diagnostic logs are written in the guest and never fetched, so the reason a "
            f"collector produced no rows dies with the instance: {stranded}"
        )

    def test_no_fetched_diagnostic_name_is_a_phantom(self) -> None:
        """Every fetched diagnostic name is one a guest script really writes."""
        produced = _guest_log_names()
        phantoms = [name for name in COLLECTOR_DIAGNOSTIC_LOG_NAMES if name not in produced]
        assert not phantoms, (
            f"the backend fetches names no guest script writes, so each costs a guest round-trip that can only fail: {phantoms}"
        )

    def test_the_fetch_list_has_no_duplicates(self) -> None:
        """A repeated name would cost an extra guest round-trip every run."""
        assert len(set(COLLECTOR_DIAGNOSTIC_LOG_NAMES)) == len(COLLECTOR_DIAGNOSTIC_LOG_NAMES), (
            f"duplicate entries in the diagnostic fetch list: {COLLECTOR_DIAGNOSTIC_LOG_NAMES}"
        )
