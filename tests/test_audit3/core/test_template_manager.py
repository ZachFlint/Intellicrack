# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U9 tests for TemplateManager log ordering on write failures.

Covers:
- F-0008: ``TemplateManager`` must only log ``*_template_file_written``
  events AFTER ``Path.write_text`` returns successfully. The pre-fix
  code logged the success event before (or regardless of) the write,
  so a failed write produced a misleading "file_written" event with no
  corresponding error event. The fix moves the success log strictly
  after the write call, and emits ``*_template_write_failed`` (or
  ``*_template_dsl_write_failed``) when ``write_text`` raises.

Each test monkey-patches ``Path.write_text`` to raise an OSError and
captures structlog events to assert:

* No ``*_template_file_written`` event was emitted.
* A ``*_template_write_failed`` event was emitted with the failing
  template path and the original error text in its structured data.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import structlog.testing

from intellicrack.core.template_manager import (
    TemplateBootstrapError,
    TemplateManager,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.types import HexDocumentFull


_TEMPLATE_NAME: str = "audit3_user_template"
_TEMPLATE_NAME_DSL: str = "audit3_user_template_with_dsl"
_TEMPLATE_NAME_BUILTIN: str = "audit3_builtin_template"
_TEMPLATE_JSON_PAYLOAD: str = '{"name": "audit3_user_template", "fields": []}'
_TEMPLATE_DSL_PAYLOAD: str = "struct Header { u32 magic; };"
_DISK_FULL_MESSAGE: str = "disk full"
_DSL_FAULT_MESSAGE: str = "dsl write failed"


def _force_write_text_failure(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    """Monkey-patch ``Path.write_text`` to always raise OSError.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        message: Error message used by the simulated OSError.
    """

    def _raise_oserror(_self: Path, *_args: object, **_kwargs: object) -> int:
        """Raise OSError to simulate a failed disk write.

        Args:
            _self: Path instance (unused; pytest signature placeholder).
            *_args: Positional arguments forwarded by ``write_text`` (unused).
            **_kwargs: Keyword arguments forwarded by ``write_text`` (unused).

        Returns:
            int: Never returns; always raises.

        Raises:
            OSError: Always raised with the configured message.
        """
        raise OSError(message)

    monkeypatch.setattr(Path, "write_text", _raise_oserror)


class _BootstrapDocumentStub:
    """Minimal HexDocumentFull stand-in for bootstrap testing.

    The real ``HexDocumentFull`` Protocol exposes many methods; bootstrap
    only invokes ``list_templates_detailed`` and ``export_template_json``,
    so this stub implements the full protocol surface but only the two
    required methods carry behaviour.

    Attributes:
        _entries: Template entries returned by ``list_templates_detailed``.
        _payload: JSON payload returned by ``export_template_json``.
    """

    def __init__(
        self,
        entries: list[tuple[str, str, str, int]],
        payload: str,
    ) -> None:
        """Initialize the document stub with template entries and payload.

        Args:
            entries: Template entries returned by ``list_templates_detailed``.
            payload: JSON payload returned by ``export_template_json``.
        """
        self._entries = entries
        self._payload = payload

    def read(self, offset: int, length: int) -> list[int]:
        """Return an empty byte list; not used by bootstrap.

        Args:
            offset: Read offset (unused).
            length: Read length (unused).

        Returns:
            list[int]: Empty list; bootstrap never reads bytes.
        """
        _ = (offset, length)
        return []

    def length(self) -> int:
        """Return zero; bootstrap does not query document length.

        Returns:
            int: Zero, fixed.
        """
        return 0

    def write(self, offset: int, data: bytes) -> None:
        """No-op; bootstrap never writes through the document.

        Args:
            offset: Write offset (unused).
            data: Write payload (unused).
        """
        _ = (offset, data)

    def list_templates(self) -> list[tuple[str, str]]:
        """Return an empty list; bootstrap uses the detailed variant.

        Returns:
            list[tuple[str, str]]: Empty list.
        """
        return []

    def list_templates_detailed(self) -> list[object]:
        """Return the seeded template entries.

        Returns:
            list[object]: Sequence of ``(name, description, category, count)``
                tuples typed as ``object`` to match the Protocol.
        """
        return list(self._entries)

    def register_json_template(self, name: str, json_str: str) -> None:
        """No-op; bootstrap does not register templates back.

        Args:
            name: Template name (unused).
            json_str: JSON payload (unused).
        """
        _ = (name, json_str)

    def remove_template(self, name: str) -> None:
        """No-op; bootstrap does not remove templates.

        Args:
            name: Template name (unused).
        """
        _ = name

    def export_template_json(self, name: str) -> str:
        """Return the canned JSON payload regardless of template name.

        Args:
            name: Template name (unused; payload is fixed for the stub).

        Returns:
            str: The seeded JSON payload string.
        """
        _ = name
        return self._payload

    def inspect_at(self, offset: int) -> dict[str, object]:
        """Return an empty dict; bootstrap does not inspect bytes.

        Args:
            offset: Byte offset (unused).

        Returns:
            dict[str, object]: Empty dict.
        """
        _ = offset
        return {}


def _make_manager(tmp_path: Path) -> TemplateManager:
    """Create a TemplateManager rooted at a temporary path.

    Args:
        tmp_path: Pytest-supplied temporary directory.

    Returns:
        TemplateManager: A manager instance whose template directory tree
            has been created on disk.
    """
    manager = TemplateManager(tmp_path)
    manager.ensure_directories()
    return manager


def _user_template_dir(config_dir: Path) -> Path:
    """Compute the user-template directory for a given config root.

    Mirrors the public layout documented by :class:`TemplateManager`:
    ``config_dir/templates/user``. Tests use this helper instead of
    reaching into a private attribute on the manager instance.

    Args:
        config_dir: Configuration directory the manager was created with.

    Returns:
        Path: Path to the user-template directory under ``config_dir``.
    """
    return config_dir / "templates" / "user"


# ---------------------------------------------------------------------------
# F-0008: save_user_template logs file_written ONLY after write_text succeeds.
# ---------------------------------------------------------------------------


def test_f0008_save_user_template_no_file_written_log_when_json_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON write failure must suppress ``user_template_file_written``.

    Pre-fix code emitted the file-written event regardless of write
    outcome, fooling consumers into trusting a non-existent file. The
    fix orders the success log strictly after a successful
    ``write_text``, so a forced failure must not produce the success
    event.
    """
    manager = _make_manager(tmp_path)
    _force_write_text_failure(monkeypatch, _DISK_FULL_MESSAGE)

    with structlog.testing.capture_logs() as captured, pytest.raises(OSError, match=_DISK_FULL_MESSAGE):
        manager.save_user_template(_TEMPLATE_NAME, _TEMPLATE_JSON_PAYLOAD)

    file_written = [c for c in captured if c.get("event") == "user_template_file_written"]
    assert not file_written, (
        f"user_template_file_written must NOT be emitted when write_text fails; captured events: {[c.get('event') for c in captured]}"
    )


def test_f0008_save_user_template_emits_write_failed_event_when_json_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON write failure must emit ``user_template_write_failed``.

    The failure event surfaces the path and error text so operators
    can locate the failing destination. Pre-fix code lacked this event
    entirely.
    """
    manager = _make_manager(tmp_path)
    _force_write_text_failure(monkeypatch, _DISK_FULL_MESSAGE)

    with structlog.testing.capture_logs() as captured, pytest.raises(OSError, match=_DISK_FULL_MESSAGE):
        manager.save_user_template(_TEMPLATE_NAME, _TEMPLATE_JSON_PAYLOAD)

    failures = [c for c in captured if c.get("event") == "user_template_write_failed"]
    assert failures, (
        f"expected user_template_write_failed event after write_text raised; captured events: {[c.get('event') for c in captured]}"
    )
    failure = failures[0]
    assert failure.get("template_name") == _TEMPLATE_NAME
    assert _DISK_FULL_MESSAGE in str(failure.get("error", ""))


def test_f0008_save_user_template_dsl_write_failure_suppresses_dsl_file_written_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DSL write failure must suppress ``user_template_dsl_file_written``.

    The DSL branch of ``save_user_template`` mirrors the JSON branch:
    success log only after a successful ``write_text``. We allow the
    JSON write to succeed (so the JSON event IS emitted) but force the
    DSL write to fail. The DSL success event must not appear; the DSL
    failure event must appear and the call must re-raise.
    """
    manager = _make_manager(tmp_path)
    user_dir = _user_template_dir(tmp_path)
    json_path = user_dir / f"{_TEMPLATE_NAME_DSL}.json"
    dsl_path = user_dir / f"{_TEMPLATE_NAME_DSL}.hexpat"

    real_write_text: Callable[[Path, str, str | None, str | None, str | None], int] = Path.write_text

    def _selective_failure(
        self: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        """Allow JSON writes; raise OSError for DSL writes.

        Args:
            self: Path being written.
            data: Text payload forwarded to the real write_text.
            encoding: Optional encoding forwarded to the real write_text.
            errors: Optional error policy forwarded to the real write_text.
            newline: Optional newline mode forwarded to the real write_text.

        Returns:
            int: Number of bytes written when the JSON path is targeted.

        Raises:
            OSError: Raised when the DSL path is targeted.
        """
        if self == dsl_path:
            raise OSError(_DSL_FAULT_MESSAGE)
        return real_write_text(self, data, encoding, errors, newline)

    monkeypatch.setattr(Path, "write_text", _selective_failure)

    with structlog.testing.capture_logs() as captured, pytest.raises(OSError, match=_DSL_FAULT_MESSAGE):
        manager.save_user_template(
            _TEMPLATE_NAME_DSL,
            _TEMPLATE_JSON_PAYLOAD,
            dsl_source=_TEMPLATE_DSL_PAYLOAD,
        )

    dsl_written = [c for c in captured if c.get("event") == "user_template_dsl_file_written"]
    dsl_failures = [c for c in captured if c.get("event") == "user_template_dsl_write_failed"]

    assert not dsl_written, (
        f"user_template_dsl_file_written must NOT fire when DSL write_text raised; captured events: {[c.get('event') for c in captured]}"
    )
    assert dsl_failures, (
        f"expected user_template_dsl_write_failed when DSL write_text raised; captured events: {[c.get('event') for c in captured]}"
    )
    failure = dsl_failures[0]
    assert failure.get("template_name") == _TEMPLATE_NAME_DSL
    assert str(failure.get("path")) == str(dsl_path)

    assert json_path.exists(), "JSON path should have been written before DSL failure"


def test_f0008_save_user_template_emits_file_written_only_after_write(
    tmp_path: Path,
) -> None:
    """Happy path: success event fires after the file actually exists.

    This is the green half of F-0008's ordering guarantee. The
    ``user_template_file_written`` event must be emitted, and the
    target file must exist on disk by the time the event is recorded.
    """
    manager = _make_manager(tmp_path)
    expected_path = _user_template_dir(tmp_path) / f"{_TEMPLATE_NAME}.json"

    with structlog.testing.capture_logs() as captured:
        returned_path = manager.save_user_template(_TEMPLATE_NAME, _TEMPLATE_JSON_PAYLOAD)

    assert returned_path == expected_path
    assert expected_path.exists()

    written_events = [c for c in captured if c.get("event") == "user_template_file_written"]
    assert written_events, (
        f"user_template_file_written must be emitted on a successful write; captured events: {[c.get('event') for c in captured]}"
    )
    assert written_events[0].get("template_name") == _TEMPLATE_NAME
    assert str(written_events[0].get("path")) == str(expected_path)


def test_f0008_bootstrap_single_template_no_file_written_log_when_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Built-in bootstrap obeys the same ordering guarantee.

    When ``Path.write_text`` raises during built-in template export,
    the success event ``builtin_template_file_written`` must not fire,
    and ``builtin_template_write_failed`` must fire instead. The
    bootstrap call must aggregate the failure and raise
    :class:`TemplateBootstrapError`.
    """
    manager = _make_manager(tmp_path)
    document: HexDocumentFull = _BootstrapDocumentStub(
        entries=[(_TEMPLATE_NAME_BUILTIN, "audit3 builtin", "common", 1)],
        payload=_TEMPLATE_JSON_PAYLOAD,
    )

    _force_write_text_failure(monkeypatch, _DISK_FULL_MESSAGE)

    with structlog.testing.capture_logs() as captured, pytest.raises(TemplateBootstrapError):
        manager.bootstrap_builtins(document)

    written = [c for c in captured if c.get("event") == "builtin_template_file_written"]
    failed = [c for c in captured if c.get("event") == "builtin_template_write_failed"]

    assert not written, (
        f"builtin_template_file_written must NOT fire when write_text raised; captured events: {[c.get('event') for c in captured]}"
    )
    assert failed, f"expected builtin_template_write_failed when write_text raised; captured events: {[c.get('event') for c in captured]}"
    failure = failed[0]
    assert failure.get("template_name") == _TEMPLATE_NAME_BUILTIN

    assert manager.failed_templates, "manager.failed_templates must record the failed write so the caller can surface the failure"
    failed_path, failed_error = manager.failed_templates[0]
    assert failed_path.name == f"{_TEMPLATE_NAME_BUILTIN}.json"
    assert _DISK_FULL_MESSAGE in failed_error
