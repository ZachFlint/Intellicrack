# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Module-level helpers of the Cutter bridge that need no backend process.

``_json_dicts``, ``_file_sha256``, ``_xref_kind`` and ``_require_openable_target`` are called directly
with real values. The expectations come from the standard library (``hashlib``), from the exceptions the
operating system raises for a locked file, and from the cross-reference types that rizin and radare2 are
documented to report.
"""

from __future__ import annotations

import ctypes
import hashlib
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path


_GENERIC_READ: Final[int] = 0x80000000
_OPEN_EXISTING: Final[int] = 3
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x80
_CHUNK_SPANNING_SIZE: Final[int] = 3 * 2**18 + 5

_json_dicts: Callable[[object], list[dict[str, Any]]] = cast(
    "Callable[[object], list[dict[str, Any]]]",
    getattr(cutter_mod, "_json_dicts"),
)
_require_openable_target: Callable[..., None] = cast(
    "Callable[..., None]",
    getattr(cutter_mod, "_require_openable_target"),
)
_file_sha256: Callable[[Path], str] = cast("Callable[[Path], str]", getattr(cutter_mod, "_file_sha256"))
_xref_kind: Callable[[str], str] = cast("Callable[[str], str]", getattr(cutter_mod, "_xref_kind"))


@pytest.fixture
def locked_file(tmp_path: Path) -> Iterator[Path]:
    """Create a file that another handle holds open with share mode zero.

    Args:
        tmp_path: Directory that receives the file.

    Yields:
        Path: The locked file; opening it for reading fails while the fixture is active.
    """
    target = tmp_path / "locked.bin"
    target.write_bytes(b"MZ\x90\x00")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = cast("int | None", kernel32.CreateFileW(str(target), _GENERIC_READ, 0, None, _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None))
    assert handle not in {None, ctypes.c_void_p(-1).value}
    try:
        yield target
    finally:
        kernel32.CloseHandle(handle)


class TestJsonDicts:
    """``_json_dicts`` keeps the objects of a parsed JSON array."""

    @pytest.mark.parametrize("value", [None, 5, "text", {"key": 1}])
    def test_non_array_values_give_an_empty_list(self, value: object) -> None:
        """A value that is not an array has no objects to keep.

        Args:
            value: A parsed JSON value that is not a list.
        """
        assert _json_dicts(value) == []

    def test_only_objects_of_an_array_are_kept_in_order(self) -> None:
        """Numbers, strings, nulls and nested arrays are dropped; objects keep their order."""
        value: list[object] = [{"a": 1}, 3, "x", None, [{"hidden": 1}], {"b": 2}]
        assert _json_dicts(value) == [{"a": 1}, {"b": 2}]


class TestFileSha256:
    """``_file_sha256`` returns the lowercase SHA-256 digest of a file's content."""

    @pytest.mark.parametrize(
        "content",
        [b"", b"abc", bytes(range(256)) * 3, bytes(index % 251 for index in range(_CHUNK_SPANNING_SIZE))],
        ids=["empty", "three-bytes", "all-byte-values", "larger-than-any-read-chunk"],
    )
    def test_digest_equals_the_standard_library_digest_of_the_bytes(self, tmp_path: Path, content: bytes) -> None:
        """The digest equals ``hashlib.sha256`` over the bytes the test wrote.

        Args:
            tmp_path: Directory that receives the file.
            content: Bytes written to the file.
        """
        target = tmp_path / "sample.bin"
        target.write_bytes(content)
        assert _file_sha256(target) == hashlib.sha256(content).hexdigest()

    def test_digest_is_sixty_four_lowercase_hex_digits_and_follows_the_content(self, tmp_path: Path) -> None:
        """The text form is 64 lowercase hex digits, and one changed byte gives a different digest.

        Args:
            tmp_path: Directory that receives the files.
        """
        first = tmp_path / "first.bin"
        second = tmp_path / "second.bin"
        first.write_bytes(b"MZ\x90\x00 payload")
        second.write_bytes(b"MZ\x90\x01 payload")
        digest = _file_sha256(first)
        assert len(digest) == hashlib.sha256().digest_size * 2
        assert digest == digest.lower()
        assert set(digest) <= set("0123456789abcdef")
        assert digest != _file_sha256(second)


class TestXrefKind:
    """``_xref_kind`` maps the backend's cross-reference type to ``call``, ``jump`` or ``data``."""

    def test_call_is_a_call(self) -> None:
        """The backends' ``CALL`` type is reported as a call."""
        assert _xref_kind("CALL") == "call"

    @pytest.mark.parametrize("raw_type", ["CODE", "JUMP", "JMP", "CJMP"])
    def test_code_references_that_are_not_calls_are_jumps(self, raw_type: str) -> None:
        """Every code-reference spelling that is not a call is reported as a jump.

        Args:
            raw_type: A code-reference type rizin or radare2 reports.
        """
        assert _xref_kind(raw_type) == "jump"

    @pytest.mark.parametrize("raw_type", ["DATA", "STRING", "UNKNOWN", ""])
    def test_anything_else_is_data(self, raw_type: str) -> None:
        """A data reference, a string reference and an unknown or empty type are all reported as data.

        Args:
            raw_type: A cross-reference type that is neither a call nor a code reference.
        """
        assert _xref_kind(raw_type) == "data"


class TestRequireOpenableTarget:
    """``_require_openable_target`` rejects what the backend would hang on."""

    def test_directory_is_not_a_regular_file(self, tmp_path: Path) -> None:
        """A directory is rejected in both modes with the not-a-regular-file reason.

        Args:
            tmp_path: Directory used as the target.
        """
        for debug in (False, True):
            with pytest.raises(ToolError) as excinfo:
                _require_openable_target(tmp_path, debug=debug)
            assert str(excinfo.value) == "failed to load binary"
            assert excinfo.value.details == {"reason": "target is not a regular file"}

    def test_locked_file_cannot_be_read(self, locked_file: Path) -> None:
        """A file held open without sharing fails to open, and the reason names the operating-system error.

        Args:
            locked_file: File held by another handle with share mode zero.
        """
        with pytest.raises(PermissionError) as os_error:
            locked_file.open("rb").close()
        with pytest.raises(ToolError) as excinfo:
            _require_openable_target(locked_file, debug=False)
        assert excinfo.value.details == {"reason": f"target cannot be read: {os_error.value}"}
        assert excinfo.value.__cause__ is not None
        assert isinstance(excinfo.value.__cause__, PermissionError)

    def test_text_file_is_refused_only_when_launched_under_the_debugger(self, tmp_path: Path) -> None:
        """A file without an executable signature opens for analysis but cannot be launched.

        Args:
            tmp_path: Directory that receives the text file.
        """
        text = tmp_path / "plain.txt"
        text.write_text("plain text\n", encoding="utf-8")
        _require_openable_target(text, debug=False)
        with pytest.raises(ToolError) as excinfo:
            _require_openable_target(text, debug=True)
        assert excinfo.value.details == {"reason": "target is not an executable image"}

    @pytest.mark.parametrize("header", [b"MZ\x90\x00", b"\x7fELF", b"#!/b"])
    def test_executable_signatures_are_accepted_for_launch(self, tmp_path: Path, header: bytes) -> None:
        """The PE, ELF and script signatures pass the debug-launch check.

        Args:
            tmp_path: Directory that receives the file.
            header: First four bytes of the file.
        """
        target = tmp_path / "image.bin"
        target.write_bytes(header + b"\x00" * 60)
        _require_openable_target(target, debug=True)
