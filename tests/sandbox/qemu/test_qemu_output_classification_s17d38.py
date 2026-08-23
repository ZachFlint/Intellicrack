# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D38: the WHPX null-MSI warning must not surface as noise.

Under WHPX with ``kernel-irqchip=on`` (see ``_build_qemu_command``), QEMU's
own in-hypervisor APIC emulation (``target/i386/whpx/whpx-apic.c``,
``whpx_send_msi``) reports every MSI whose vector field is 0 with
``warn_report("Ignoring request for interrupt vector 0")`` - a "null" MSI with
nothing to deliver, dropped rather than injected. That line is APIC
housekeeping a guest performs on its own during ordinary boot under WHPX, not
evidence of an accelerator fault, and QEMU has been observed writing it to its
own stderr - carried into the sandbox through
:meth:`~intellicrack.sandbox.qemu.QemuOutputRecorder._retain`.

Only this one line is exempted. Every other line QEMU tags with its own
``warning:`` convention (``warn_report()`` is used throughout the QEMU tree,
not only for this message) must still surface at the level an operator would
notice - demoting more than the one known-benign line would hide a genuine
fault behind the same reasoning that excuses this one, which is exactly what
the project's "don't silence warnings" rule forbids.
:meth:`QemuOutputRecorder._classify_output_line` is the pure function both
properties are gated against, and :meth:`QemuOutputRecorder._retain` is
checked directly against the module logger to confirm the classification
actually reaches a different log level rather than only existing on paper.
Both are reached through :class:`_TestableOutputRecorder`, a subclass adding
nothing but public wrappers around the two real production methods.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal, cast

from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.qemu import QemuOutputRecorder


if TYPE_CHECKING:
    import asyncio

    import pytest


_WHPX_NULL_MSI_LINE: Final[str] = "qemu-system-x86_64: warning: Ignoring request for interrupt vector 0"
_WHPX_NULL_MSI_LINE_BARE: Final[str] = "warning: Ignoring request for interrupt vector 0"
_GENUINE_WARNING_LINE: Final[str] = "qemu-system-x86_64: warning: TCP_NODELAY failed: Unknown error"
_ROUTINE_LINE: Final[str] = "VNC server running on 127.0.0.1:5900"

_BENIGN: Final[str] = "benign"
_WARNING: Final[str] = "warning"
_ROUTINE: Final[str] = "routine"


class _TestableOutputRecorder(QemuOutputRecorder):
    """``QemuOutputRecorder`` subclass exposing its classification internals.

    Only public wrappers are added; every wrapped method is the real
    production implementation, matching the pattern already established for
    ``QEMUSandbox`` in ``test_guest_agent_channel_retention_s17d57.py``.
    """

    def classify(self, text: str) -> Literal["benign", "warning", "routine"]:
        """Classify one output line the way the recorder itself does.

        Args:
            text: One line of QEMU's stdout or stderr, already stripped.

        Returns:
            Literal["benign", "warning", "routine"]: The production
            classification for ``text``.
        """
        return self._classify_output_line(text)

    def retain(self, line: str, channel: str) -> None:
        """Log and retain one output line the way the recorder itself does.

        Args:
            line: The line QEMU emitted, without its terminator.
            channel: Stream name the line arrived on.
        """
        self._retain(line, channel)


def _make_recorder() -> _TestableOutputRecorder:
    """Build a recorder around a process double the tests never run.

    Returns:
        _TestableOutputRecorder: Recorder ready for direct method calls.
    """
    return _TestableOutputRecorder(process=cast("asyncio.subprocess.Process", object()))


class TestTheWhpxNullMsiWarningIsClassifiedBenign:
    """The one documented, harmless WHPX warning must not surface as noise."""

    def test_the_exact_whpx_line_is_benign(self) -> None:
        """QEMU's real ``warn_report`` line, with its process-name prefix, is benign."""
        classification = _make_recorder().classify(_WHPX_NULL_MSI_LINE)
        assert classification == _BENIGN, (
            f"the WHPX null-MSI warning was classified {classification!r} instead of {_BENIGN!r}; line={_WHPX_NULL_MSI_LINE!r}"
        )

    def test_the_bare_message_without_the_process_prefix_is_also_benign(self) -> None:
        """The marker match must not depend on QEMU's process-name prefix."""
        classification = _make_recorder().classify(_WHPX_NULL_MSI_LINE_BARE)
        assert classification == _BENIGN, (
            f"the WHPX null-MSI warning was classified {classification!r} instead of {_BENIGN!r}; line={_WHPX_NULL_MSI_LINE_BARE!r}"
        )


class TestADifferentGenuineWarningStillSurfacesNormally:
    """The discriminator: only the one known line is demoted, nothing else."""

    def test_a_different_warning_line_is_classified_warning_not_benign(self) -> None:
        """A real, unrelated QEMU warning must keep surfacing at its normal level."""
        classification = _make_recorder().classify(_GENUINE_WARNING_LINE)
        assert classification == _WARNING, (
            f"an unrelated genuine QEMU warning was classified {classification!r} instead of {_WARNING!r}; "
            f"line={_GENUINE_WARNING_LINE!r} - demoting more than the one known-benign line hides real faults"
        )

    def test_routine_output_carrying_neither_marker_is_classified_routine(self) -> None:
        """Ordinary QEMU output with no warning marker at all stays routine."""
        classification = _make_recorder().classify(_ROUTINE_LINE)
        assert classification == _ROUTINE, (
            f"ordinary QEMU output was classified {classification!r} instead of {_ROUTINE!r}; line={_ROUTINE_LINE!r}"
        )


class _RecordingLogger:
    """Fake structlog-shaped logger recording which level each call used."""

    def __init__(self) -> None:
        """Initialise the recorder with no calls made yet.

        The ``levels`` instance attribute accumulates the name of every level
        method invoked, in call order.
        """
        self.levels: list[str] = []

    def debug(self, *args: object, **kwargs: object) -> None:
        """Record a debug-level call.

        Args:
            *args: Positional arguments the caller passed.
            **kwargs: Keyword arguments the caller passed.
        """
        del args, kwargs
        self.levels.append("debug")

    def warning(self, *args: object, **kwargs: object) -> None:
        """Record a warning-level call.

        Args:
            *args: Positional arguments the caller passed.
            **kwargs: Keyword arguments the caller passed.
        """
        del args, kwargs
        self.levels.append("warning")


class TestTheRecorderLogsEachClassificationAtItsOwnLevel:
    """The classification must actually reach the log at a matching level."""

    def test_retain_logs_the_benign_line_at_debug_not_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The benign WHPX line must be logged, but never at ``warning``.

        Args:
            monkeypatch: Standard pytest fixture, used to swap the module's
                bound logger for one that records which level was called.
        """
        recording = _RecordingLogger()
        monkeypatch.setattr(qemu_module, "_logger", recording)

        _make_recorder().retain(_WHPX_NULL_MSI_LINE, "stderr")

        assert "warning" not in recording.levels, f"the benign WHPX line reached logger.warning(...); levels={recording.levels!r}"
        assert "debug" in recording.levels, f"the benign WHPX line was not logged at all; levels={recording.levels!r}"

    def test_retain_logs_a_genuine_warning_line_at_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A genuine warning line must reach ``logger.warning(...)``.

        Args:
            monkeypatch: Standard pytest fixture, used to swap the module's
                bound logger for one that records which level was called.
        """
        recording = _RecordingLogger()
        monkeypatch.setattr(qemu_module, "_logger", recording)

        _make_recorder().retain(_GENUINE_WARNING_LINE, "stderr")

        assert "warning" in recording.levels, f"a genuine QEMU warning line never reached logger.warning(...); levels={recording.levels!r}"
