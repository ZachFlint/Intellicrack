# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for the large fixture files: big in size, small on disk, on every platform.

The install-media and patch-source gates build files of two and three gibibytes
that carry a few sectors of real data. They were extended with a bare
``truncate``, which leaves a hole on Linux but allocates the whole extension on
NTFS, so a single Windows run held some thirty-four gibibytes of zeros in
pytest's temporary directories and the hosted runner ran out of disk partway
through the suite. These tests hold :func:`tests._helpers.sparse_files.extend_sparse`
to the property those fixtures depend on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from tests._helpers.sparse_files import allocated_bytes, extend_sparse


if TYPE_CHECKING:
    from pathlib import Path


_FIXTURE_BYTES: Final[int] = 256 * 1024 * 1024
_HEADER: Final[bytes] = b"real header bytes" * 64
_HEADER_OFFSET: Final[int] = 32768
_ALLOWED_ON_DISK_BYTES: Final[int] = _FIXTURE_BYTES // 2
"""How much real disk the fixture may occupy: half of its size.

A sparse file still occupies something, and how much depends on the volume rather than on the file: about one megabyte for this fixture
on a workstation, and seventeen and then thirty-four on two runs of the hosted CI runner. Extended with a bare ``truncate`` it occupies
all of its size, which is the difference this bound has to tell apart, so it is set well clear of both.
"""
_TAIL_PROBE_BYTES: Final[int] = 4096


def _fixture(path: Path) -> Path:
    """Write a fixture with a small header and a large empty tail.

    Args:
        path: Destination file.

    Returns:
        Path: The written file.
    """
    with path.open("wb") as handle:
        _ = handle.seek(_HEADER_OFFSET)
        _ = handle.write(_HEADER)
        extend_sparse(handle, _FIXTURE_BYTES)
    return path


def test_a_sparse_fixture_has_its_full_size_and_stores_almost_nothing(tmp_path: Path) -> None:
    """The fixture reports the size it was extended to while occupying next to no disk.

    Falsifiable: extended with a bare ``truncate``, the same file occupies its
    whole size on NTFS, which is what filled the runner's disk.

    Args:
        tmp_path: Per-test directory.
    """
    fixture = _fixture(tmp_path / "media.iso")

    assert fixture.stat().st_size == _FIXTURE_BYTES
    on_disk = allocated_bytes(fixture)
    assert on_disk < _ALLOWED_ON_DISK_BYTES, f"a {_FIXTURE_BYTES}-byte fixture occupies {on_disk} bytes of real disk"


def test_a_sparse_fixture_keeps_its_data_and_reads_zeros_past_it(tmp_path: Path) -> None:
    """What was written before the extension is intact, and the extension reads back as zeros.

    Args:
        tmp_path: Per-test directory.
    """
    fixture = _fixture(tmp_path / "media.iso")

    with fixture.open("rb") as handle:
        _ = handle.seek(_HEADER_OFFSET)
        assert handle.read(len(_HEADER)) == _HEADER
        _ = handle.seek(_FIXTURE_BYTES - _TAIL_PROBE_BYTES)
        assert handle.read(_TAIL_PROBE_BYTES) == bytes(_TAIL_PROBE_BYTES)
