# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, items 11 and 46: a chunked credential is written as a transaction, by one writer at a time, and never read half-changed.

Every gate runs against a real file-backed keyring in the test's own directory. A write that fails part-way -- the keyring runs out of
room -- must leave no chunk behind and the previous value intact, and must tell the operator the keyring is full. A process killed in the
middle of a chunked write leaves orphans that the next write or delete removes. Two stores writing the same credential from two threads
leave exactly one complete set of chunks, and a reader running against a writer never sees a missing chunk.
"""

from __future__ import annotations

import asyncio
import base64
import configparser
import os
import subprocess
import sys
import textwrap
import threading
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import ChunkManifest, CredentialStore, CredentialStoreFullError, KeyringReadError
from tests._helpers.private_keyring import (
    CredentialManagerSizedKeyring,
    FullKeyring,
    file_keyring_entry_name,
    installed_keyring,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from keyring.backend import KeyringBackend


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_LARGE_CHARS: Final[int] = 9000
_CRASH_EXIT: Final[int] = 3
_CHILD_TIMEOUT_S: Final[float] = 120.0
_WRITER_ROUNDS: Final[int] = 12
_READER_ROUNDS: Final[int] = 60


def _entries(keyring_file: Path, service: str) -> dict[str, str]:
    """Read every entry the file keyring holds for one service, straight from its file.

    Args:
        keyring_file: The keyring file.
        service: The service name.

    Returns:
        dict[str, str]: Each entry's on-disk name and its decoded value.
    """
    parser = configparser.RawConfigParser()
    _ = parser.read(keyring_file, encoding="utf-8")
    section = file_keyring_entry_name(service)
    if not parser.has_section(section):
        return {}
    return {option: base64.decodebytes(parser.get(section, option).encode()).decode("utf-8") for option in parser.options(section)}


def _chunk_entries(keyring_file: Path, service: str) -> list[str]:
    """List the chunk and pending-marker entries in the keyring file.

    Args:
        keyring_file: The keyring file.
        service: The service name.

    Returns:
        list[str]: Their on-disk names.
    """
    infix = file_keyring_entry_name("__chunk_").lower()
    return [name for name in _entries(keyring_file, service) if infix in name.lower()]


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> str:
    """Give every store in the test a private service name.

    Args:
        monkeypatch: Restores the service name afterwards.

    Returns:
        str: The service name.
    """
    name = f"intellicrack-tx-{uuid.uuid4().hex}"
    monkeypatch.setattr(CredentialStore, "SERVICE_NAME", name)
    return name


def _store(tmp_path: Path) -> CredentialStore:
    """Build a store whose env-file fallback is the test's own.

    Args:
        tmp_path: Per-test directory.

    Returns:
        CredentialStore: The store, on whatever keyring is installed.
    """
    store = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))
    assert store.keyring_available
    return store


@pytest.fixture
def sized(tmp_path: Path, service: str) -> Iterator[tuple[KeyringBackend, Path]]:
    """Install a keyring with Credential Manager's blob limit over a private file.

    Args:
        tmp_path: Per-test directory.
        service: The private service name.

    Yields:
        tuple[KeyringBackend, Path]: The backend and its file.
    """
    del service
    keyring_file = tmp_path / "keyring.cfg"
    backend = CredentialManagerSizedKeyring(keyring_file)
    with installed_keyring(backend):
        yield backend, keyring_file


class TestFailedWriteLeavesNothingBehind:
    """A chunked write the keyring runs out of room for is undone, and the operator is told why."""

    def test_full_keyring_keeps_the_previous_value_and_no_chunks(self, tmp_path: Path, service: str) -> None:
        """The previous value reads back unchanged, no chunk of the failed write remains, and the error says the keyring is full.

        Args:
            tmp_path: Per-test directory.
            service: The private service name.
        """
        keyring_file = tmp_path / "keyring.cfg"
        with installed_keyring(FullKeyring(keyring_file, capacity=6)):
            store = _store(tmp_path)
            asyncio.run(store.set("full", ProviderCredentials(api_key="before")))
            before = _entries(keyring_file, service)

            with pytest.raises(CredentialStoreFullError) as caught:
                asyncio.run(store.set("full", ProviderCredentials(api_key="L" * _LARGE_CHARS)))

            loaded = asyncio.run(store.get_secret("full"))

        assert "keyring is full" in str(caught.value)
        assert "Credential Manager" in str(caught.value)
        assert "stored before is unchanged" in str(caught.value)
        assert loaded is not None
        assert loaded.api_key == "before"
        assert _chunk_entries(keyring_file, service) == []
        assert _entries(keyring_file, service) == before


class TestInterruptedWriteIsRecovered:
    """Chunks a killed process was writing are removed by the next write or delete."""

    @staticmethod
    def _crash_mid_write(tmp_path: Path, service: str, keyring_file: Path) -> None:
        """Start a chunked write in a child process that is killed after its third chunk.

        Args:
            tmp_path: Per-test directory.
            service: The private service name.
            keyring_file: The keyring file both processes use.
        """
        code = f"""
            import asyncio, os
            from intellicrack.core.types import ProviderCredentials
            from intellicrack.credentials.env_loader import CredentialLoader
            from intellicrack.credentials.store import CredentialStore
            from tests._helpers.private_keyring import CredentialManagerSizedKeyring, installed_keyring

            class Killed(CredentialManagerSizedKeyring):
                writes = 0
                def set_password(self, service, username, password):
                    super().set_password(service, username, password)
                    Killed.writes += 1
                    if Killed.writes == 4:
                        os._exit({_CRASH_EXIT})

            CredentialStore.SERVICE_NAME = {service!r}
            with installed_keyring(Killed(__import__("pathlib").Path({str(keyring_file)!r}))):
                store = CredentialStore(fallback_loader=CredentialLoader(env_path=__import__("pathlib").Path({str(tmp_path / ".env")!r})))
                asyncio.run(store.set("crashed", ProviderCredentials(api_key="C" * {_LARGE_CHARS})))
        """
        env = {**os.environ, "PYTHONPATH": f"{_REPO_ROOT / 'src'}{os.pathsep}{_REPO_ROOT}"}
        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code)],
            capture_output=True,
            text=True,
            timeout=_CHILD_TIMEOUT_S,
            env=env,
            check=False,
        )
        assert completed.returncode == _CRASH_EXIT, completed.stderr

    def test_next_write_removes_the_orphans(self, tmp_path: Path, service: str, sized: tuple[KeyringBackend, Path]) -> None:
        """After the crash some chunks are left; after the next write only the new value's chunks exist.

        Args:
            tmp_path: Per-test directory.
            service: The private service name.
            sized: The installed backend and its file.
        """
        backend, keyring_file = sized
        self._crash_mid_write(tmp_path, service, keyring_file)
        assert _chunk_entries(keyring_file, service), "the killed write left nothing to recover"

        store = _store(tmp_path)
        asyncio.run(store.set("crashed", ProviderCredentials(api_key="N" * _LARGE_CHARS)))

        manifest = ChunkManifest.parse(backend.get_password(service, f"{service}_crashed") or "")
        assert manifest is not None
        assert len(_chunk_entries(keyring_file, service)) == manifest.count
        loaded = asyncio.run(store.get_secret("crashed"))
        assert loaded is not None
        assert loaded.api_key == "N" * _LARGE_CHARS

    def test_delete_removes_the_orphans(self, tmp_path: Path, service: str, sized: tuple[KeyringBackend, Path]) -> None:
        """Deleting the credential after the crash leaves no chunk at all.

        Args:
            tmp_path: Per-test directory.
            service: The private service name.
            sized: The installed backend and its file.
        """
        _, keyring_file = sized
        self._crash_mid_write(tmp_path, service, keyring_file)
        store = _store(tmp_path)
        asyncio.run(store.set("crashed", ProviderCredentials(api_key="small")))

        assert asyncio.run(store.delete("crashed")) is True
        assert _chunk_entries(keyring_file, service) == []


class TestConcurrentAccess:
    """Stores in different threads never orphan each other's chunks or read a half-switched value."""

    def test_two_writers_leave_one_complete_set(self, tmp_path: Path, service: str, sized: tuple[KeyringBackend, Path]) -> None:
        """Two stores rewriting the same large credential at once end with exactly the chunks its manifest names.

        Args:
            tmp_path: Per-test directory.
            service: The private service name.
            sized: The installed backend and its file.
        """
        backend, keyring_file = sized
        failures: list[BaseException] = []

        def write(letter: str) -> None:
            store = _store(tmp_path)
            try:
                for round_index in range(_WRITER_ROUNDS):
                    asyncio.run(store.set("shared", ProviderCredentials(api_key=f"{letter}{round_index}" * (_LARGE_CHARS // 3))))
            except BaseException as exc:
                failures.append(exc)
                raise

        threads = [threading.Thread(target=write, args=(letter,)) for letter in "AB"]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert failures == []
        manifest = ChunkManifest.parse(backend.get_password(service, f"{service}_shared") or "")
        assert manifest is not None
        assert len(_chunk_entries(keyring_file, service)) == manifest.count

    def test_reader_never_sees_a_missing_chunk(self, tmp_path: Path, sized: tuple[KeyringBackend, Path]) -> None:
        """A reader in one thread and a writer in another: every read returns one whole value.

        Args:
            tmp_path: Per-test directory.
            sized: The installed backend and its file.
        """
        del sized
        writer_store = _store(tmp_path)
        values = [letter * _LARGE_CHARS for letter in "PQ"]
        asyncio.run(writer_store.set("read", ProviderCredentials(api_key=values[0])))
        stop = threading.Event()
        failures: list[BaseException] = []

        def rewrite() -> None:
            index = 0
            while not stop.is_set():
                index += 1
                asyncio.run(writer_store.set("read", ProviderCredentials(api_key=values[index % 2])))

        writer = threading.Thread(target=rewrite)
        writer.start()
        reader_store = _store(tmp_path)
        seen: list[str] = []
        try:
            for _ in range(_READER_ROUNDS):
                try:
                    loaded = asyncio.run(reader_store.get_secret("read"))
                except KeyringReadError as exc:
                    failures.append(exc)
                    continue
                assert loaded is not None
                assert loaded.api_key is not None
                seen.append(loaded.api_key)
        finally:
            stop.set()
            writer.join()

        assert failures == []
        assert set(seen) <= set(values)
