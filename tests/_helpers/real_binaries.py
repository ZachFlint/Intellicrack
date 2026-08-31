# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Locators for real binary fixtures used by Intellicrack tests.

Intellicrack's binary-analysis tests must operate on genuine, compiled
executables rather than synthetic byte blobs. This module provides two
families of helpers:

* Runtime resolvers that locate REAL Portable Executable (PE) binaries that
  already exist on the running Windows system. They work both on a developer's
  Windows host and inside the Windows Docker test container (workspace at
  ``C:/app``), where ``C:/Windows/System32`` holds the standard system DLLs and
  executables.
* Corpus loaders that return the committed REAL ELF and Mach-O fixtures stored
  under ``tests/fixtures/binaries/``. These formats cannot be sourced from a
  Windows system at runtime, so authentic compiled samples are committed to the
  repository and validated against their recorded magic bytes.

Every resolver validates that the file exists and begins with the correct
format magic before returning it, so a test that receives a path is guaranteed
a real binary of the expected format. When a target is genuinely unavailable
the helpers raise :class:`FixtureUnavailableError`, which the pytest fixtures
translate into a precise ``pytest.skip`` reason rather than a fabricated pass.
"""

from __future__ import annotations

import sys
from pathlib import Path


__all__ = [
    "FIXTURES_DIR",
    "FixtureUnavailableError",
    "load_real_elf",
    "load_real_macho",
    "resolve_real_pe_dll",
    "resolve_real_pe_dlls",
    "resolve_real_pe_exe",
]


FIXTURES_DIR: Path = Path(__file__).resolve().parent.parent / "fixtures" / "binaries"
"""Absolute path to the committed binary fixture directory."""

_PE_MAGIC: bytes = b"MZ"
_ELF_MAGIC: bytes = b"\x7fELF"
_MACHO_MAGICS: tuple[bytes, ...] = (
    b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit, big-endian)
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (64-bit, big-endian)
    b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit, little-endian)
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (64-bit, little-endian)
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal, big-endian)
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM (universal, little-endian)
)

_SYSTEM32: Path = Path("C:/Windows/System32")
_PE_DLL_NAME: str = "kernel32.dll"
_PE_DLL_NAMES: tuple[str, ...] = ("kernel32.dll", "ntdll.dll", "user32.dll")
_PE_EXE_NAMES: tuple[str, ...] = ("notepad.exe", "cmd.exe", "where.exe", "tasklist.exe")

_ELF_FIXTURE_NAME: str = "true_x86_64"
_MACHO_FIXTURE_NAME: str = "macho_osx_x64_ls"


class FixtureUnavailableError(RuntimeError):
    """Raised when a requested real-binary fixture cannot be provided.

    The pytest fixtures catch this and convert the message into a precise
    ``pytest.skip`` reason, so a missing fixture never causes a fabricated
    pass or a misleading failure.
    """


def _read_magic(path: Path, length: int) -> bytes:
    """Read the first ``length`` bytes of ``path``.

    Args:
        path: File whose leading bytes to read.
        length: Number of leading bytes to read.

    Returns:
        bytes: The leading bytes actually read, which may be shorter than
            ``length`` if the file is smaller.

    Raises:
        FixtureUnavailableError: If the file cannot be opened or read.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(length)
    except OSError as exc:
        message = f"Cannot read magic bytes from {path}: {exc}"
        raise FixtureUnavailableError(message) from exc


def _require_file(path: Path) -> Path:
    """Validate that ``path`` exists and is a regular file.

    Args:
        path: Candidate file path.

    Returns:
        Path: The validated path.

    Raises:
        FixtureUnavailableError: If the path does not exist or is not a file.
    """
    if not path.exists():
        message = f"Required binary does not exist: {path}"
        raise FixtureUnavailableError(message)
    if not path.is_file():
        message = f"Required binary path is not a regular file: {path}"
        raise FixtureUnavailableError(message)
    return path


def _require_pe(path: Path) -> Path:
    """Validate that ``path`` is an existing file beginning with the MZ magic.

    Args:
        path: Candidate PE file path.

    Returns:
        Path: The validated PE path.

    Raises:
        FixtureUnavailableError: If the file is missing or lacks the MZ magic.
    """
    _require_file(path)
    magic = _read_magic(path, len(_PE_MAGIC))
    if magic != _PE_MAGIC:
        message = f"File {path} is not a PE binary (magic {magic!r} != {_PE_MAGIC!r})"
        raise FixtureUnavailableError(message)
    return path


def _ensure_windows(target_description: str) -> None:
    """Ensure the current platform is Windows for a PE resolver.

    Args:
        target_description: Human-readable description of the target being
            resolved, used in the skip reason.

    Raises:
        FixtureUnavailableError: If the current platform is not Windows.
    """
    if sys.platform != "win32":
        message = f"{target_description} requires a Windows system (current platform: {sys.platform})"
        raise FixtureUnavailableError(message)


def resolve_real_pe_dll() -> Path:
    """Locate a real PE DLL present on the running Windows system.

    Resolves ``C:/Windows/System32/kernel32.dll`` and validates it begins with
    the MZ magic. Works on both a Windows host and inside the Windows Docker
    test container. Raises :class:`FixtureUnavailableError` (via its helpers)
    when not on Windows or the DLL is absent or not a valid PE binary.

    Returns:
        Path: Validated path to a real PE DLL.
    """
    _ensure_windows("Resolving a real PE DLL")
    return _require_pe(_SYSTEM32 / _PE_DLL_NAME)


def resolve_real_pe_dlls() -> list[Path]:
    """Locate several real PE DLLs present on the running Windows system.

    Resolves the standard system DLLs ``kernel32.dll``, ``ntdll.dll`` and
    ``user32.dll`` from ``C:/Windows/System32`` and validates each begins with
    the MZ magic. Any DLL that is genuinely absent is skipped; the function
    returns every DLL it could validate.

    Returns:
        list[Path]: One or more validated paths to real PE DLLs.

    Raises:
        FixtureUnavailableError: If not on Windows, or none of the candidate
            DLLs could be validated.
    """
    _ensure_windows("Resolving real PE DLLs")
    resolved: list[Path] = []
    for name in _PE_DLL_NAMES:
        candidate = _SYSTEM32 / name
        try:
            resolved.append(_require_pe(candidate))
        except FixtureUnavailableError:
            continue
    if not resolved:
        message = f"No real PE DLLs could be resolved from {_SYSTEM32} (tried {', '.join(_PE_DLL_NAMES)})"
        raise FixtureUnavailableError(message)
    return resolved


def resolve_real_pe_exe() -> Path:
    """Locate a real PE executable present on the running Windows system.

    Prefers ``C:/Windows/System32/notepad.exe`` and falls back to other common
    System32 executables (``cmd.exe``, ``where.exe``, ``tasklist.exe``). Each
    candidate is validated to begin with the MZ magic.

    Returns:
        Path: Validated path to a real PE executable.

    Raises:
        FixtureUnavailableError: If not on Windows, or none of the candidate
            executables could be validated.
    """
    _ensure_windows("Resolving a real PE executable")
    for name in _PE_EXE_NAMES:
        candidate = _SYSTEM32 / name
        try:
            return _require_pe(candidate)
        except FixtureUnavailableError:
            continue
    message = f"No real PE executable could be resolved from {_SYSTEM32} (tried {', '.join(_PE_EXE_NAMES)})"
    raise FixtureUnavailableError(message)


def _load_corpus_binary(name: str, magics: tuple[bytes, ...], fmt: str) -> Path:
    """Load a committed corpus binary and validate its format magic.

    Args:
        name: Filename of the fixture inside :data:`FIXTURES_DIR`.
        magics: Accepted leading-magic byte sequences for the format.
        fmt: Human-readable format label used in error messages.

    Returns:
        Path: Validated path to the corpus binary.

    Raises:
        FixtureUnavailableError: If the fixture is missing or its leading
            bytes do not match any accepted magic for the format.
    """
    path = FIXTURES_DIR / name
    _require_file(path)
    max_len = max(len(magic) for magic in magics)
    header = _read_magic(path, max_len)
    if not any(header.startswith(magic) for magic in magics):
        message = f"Committed {fmt} fixture {path} has unexpected magic {header!r}; fixture may be corrupt"
        raise FixtureUnavailableError(message)
    return path


def load_real_elf() -> Path:
    """Load the committed real ELF fixture from the binary corpus.

    Raises :class:`FixtureUnavailableError` (via :func:`_load_corpus_binary`)
    when the ELF fixture is missing or its magic bytes do not match the ELF
    format.

    Returns:
        Path: Validated path to the committed ELF binary.
    """
    return _load_corpus_binary(_ELF_FIXTURE_NAME, (_ELF_MAGIC,), "ELF")


def load_real_macho() -> Path:
    """Load the committed real Mach-O fixture from the binary corpus.

    Raises :class:`FixtureUnavailableError` (via :func:`_load_corpus_binary`)
    when the Mach-O fixture is missing or its magic bytes do not match any
    Mach-O format variant.

    Returns:
        Path: Validated path to the committed Mach-O binary.
    """
    return _load_corpus_binary(_MACHO_FIXTURE_NAME, _MACHO_MAGICS, "Mach-O")
