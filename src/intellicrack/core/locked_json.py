# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A small JSON document on disk that several threads and processes may change at once.

The operator's trust decisions and remembered approvals each live in one JSON file, written from the GUI thread and from the background
loop alike. A plain read-modify-write through one fixed temporary file loses data three ways: two writers interleave and the second
overwrites the first's change; on Windows a reader holding the file open makes the writer's rename fail with ``WinError 5``; and two
writers sharing the temporary file corrupt it. Worse, a corrupt read treated as an empty document makes the next write wipe every record.

:class:`LockedJsonFile` closes all three. Every read and every read-modify-write holds an exclusive lock -- a thread lock within the
process and an operating-system lock on a sidecar file across processes -- so no two changes interleave and no reader has the file open
while it is replaced. Each write goes to a temporary file of its own in the same directory and is renamed over the document. And a change
is only ever applied to a document that was read successfully: a document that cannot be read or parsed is left exactly as it is, and the
change is refused with :class:`JsonDocumentError`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from intellicrack.core.json_payload import JsonObject, is_json_object
from intellicrack.core.logging import get_logger


if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

if TYPE_CHECKING:
    from collections.abc import Callable, Generator


_logger = get_logger(__name__)

_LOCK_SUFFIX: Final[str] = ".lock"

_REPLACE_ATTEMPTS: Final[int] = 8
"""How often a rename refused by a sharing violation is tried before the write is reported as failed."""

_REPLACE_BACKOFF_S: Final[float] = 0.02
"""First wait between rename attempts; each later wait doubles it."""

_WINDOWS_LOCK_BYTES: Final[int] = 1

_locks_guard = threading.Lock()
_thread_locks: dict[str, threading.RLock] = {}


class JsonDocumentError(OSError):
    """A JSON document could not be read, or a change to it could not be written.

    Raised instead of applying a change to a document that was not read, so a
    transient read failure or a corrupt file can never be overwritten with a
    near-empty one.
    """


def _thread_lock(path: Path) -> threading.RLock:
    """Return the in-process lock guarding one document.

    Args:
        path: The document, resolved.

    Returns:
        threading.RLock: The lock every thread in this process takes.
    """
    key = os.path.normcase(str(path))
    with _locks_guard:
        lock = _thread_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _thread_locks[key] = lock
        return lock


@contextmanager
def _process_lock(lock_path: Path) -> Generator[None]:
    """Hold an exclusive operating-system lock on a sidecar file.

    Args:
        lock_path: The sidecar file, created when absent.

    Yields:
        None: Control passes to the block holding the lock.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if sys.platform == "win32":
            _ = handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, _WINDOWS_LOCK_BYTES)
            try:
                yield
            finally:
                _ = handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, _WINDOWS_LOCK_BYTES)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _replace(source: Path, target: Path) -> None:
    """Rename a file over another, riding out a transient sharing violation.

    On Windows a rename onto a file another process has open without
    delete sharing -- a virus scanner, a search indexer -- fails with
    ``WinError 5`` until that handle closes. Every reader in this process
    holds the document lock, so only such an outside handle can cause it.

    Args:
        source: The file to move.
        target: Where it goes.

    Raises:
        JsonDocumentError: If the rename still fails after every attempt.
    """
    delay = _REPLACE_BACKOFF_S
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            _ = source.replace(target)
        except PermissionError as exc:
            if attempt == _REPLACE_ATTEMPTS - 1:
                message = f"cannot replace {target}: {exc}"
                raise JsonDocumentError(message) from exc
            time.sleep(delay)
            delay *= 2
        else:
            return


class LockedJsonFile:
    """One JSON object on disk, read and changed only under an exclusive lock."""

    def __init__(self, path: Path) -> None:
        """Bind to a document.

        Args:
            path: The document's path. It need not exist yet.
        """
        self._path = path

    @property
    def path(self) -> Path:
        """The document's path.

        Returns:
            Path: The path.
        """
        return self._path

    @contextmanager
    def _locked(self) -> Generator[Path]:
        """Hold both locks on the document.

        Yields:
            Path: The resolved document path.
        """
        resolved = self._path.resolve()
        with _thread_lock(resolved), _process_lock(resolved.with_name(f"{resolved.name}{_LOCK_SUFFIX}")):
            yield resolved

    @staticmethod
    def _load(path: Path) -> JsonObject:
        """Read and decode the document, refusing anything that is not a JSON object.

        Args:
            path: The resolved document path.

        Returns:
            JsonObject: The document, or an empty object when the file does
            not exist.

        Raises:
            JsonDocumentError: If the file exists but cannot be read, is not
                valid JSON, or is not a JSON object.
        """
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeDecodeError) as exc:
            message = f"cannot read {path}: {exc}"
            raise JsonDocumentError(message) from exc
        try:
            decoded: object = json.loads(raw)
        except json.JSONDecodeError as exc:
            message = f"{path} is not valid JSON: {exc}"
            raise JsonDocumentError(message) from exc
        if not is_json_object(decoded):
            message = f"{path} does not hold a JSON object"
            raise JsonDocumentError(message)
        return decoded

    def read(self) -> JsonObject:
        """Read the document.

        A document that exists but cannot be read or parsed propagates
        :class:`JsonDocumentError`.

        Returns:
            JsonObject: The document, or an empty object when it does not
            exist.
        """
        with self._locked() as path:
            return self._load(path)

    def read_or_empty(self) -> JsonObject:
        """Read the document, treating a fault as an empty document.

        For callers that only look: an unreadable document answers "nothing
        recorded", which is the safe direction for a read. A change never goes
        through this path.

        Returns:
            JsonObject: The document, or an empty object when it does not
            exist or cannot be read.
        """
        try:
            return self.read()
        except JsonDocumentError as exc:
            _logger.warning("json_document_unreadable", path=str(self._path), error=str(exc))
            return {}

    def update(self, change: Callable[[JsonObject], bool]) -> JsonObject:
        """Apply a change to the document atomically.

        The document is read, changed and written back while the lock is
        held, so no other change can interleave. The new content goes to a
        temporary file of its own and is renamed over the document.

        Args:
            change: Mutates the decoded document in place and returns whether
                it changed anything; nothing is written when it returns
                ``False``.

        A document that could not be read propagates
        :class:`JsonDocumentError` and is left untouched; so does new content
        that could not be written.

        Returns:
            JsonObject: The document as it now stands.
        """
        with self._locked() as path:
            document = self._load(path)
            if not change(document):
                return document
            self._write(path, document)
            return document

    @staticmethod
    def _write(path: Path, document: dict[str, Any]) -> None:
        """Write a document through a temporary file of its own.

        Args:
            path: The resolved document path.
            document: The content to write.

        Raises:
            JsonDocumentError: If the content could not be written.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = f"{json.dumps(document, indent=2, sort_keys=True)}\n"
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f"{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                _ = handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
        except OSError as exc:
            message = f"cannot write {path}: {exc}"
            raise JsonDocumentError(message) from exc
        try:
            _replace(temporary, path)
        except JsonDocumentError:
            temporary.unlink(missing_ok=True)
            raise
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            message = f"cannot replace {path}: {exc}"
            raise JsonDocumentError(message) from exc


__all__ = ["JsonDocumentError", "LockedJsonFile"]
