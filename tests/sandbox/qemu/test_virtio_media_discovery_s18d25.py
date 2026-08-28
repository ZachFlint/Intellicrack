# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S18-D25: the staged virtio medium was unreachable by discovery.

Measured on a real provisioning run. The install medium was found in
``D:\Intellicrack\tools\qemu\images`` and verified, and the very next step
failed on a virtio-win ISO sitting in that same directory:

```
install_media_verified  image=D:\...\images\Windows11-NoPrompt.iso
ProvisioningError: virtio-win driver ISO not found on this host ...
```

The two searches were not given the same roots. Install media is discovered
with the Intellicrack images directory as a priority root, so it is scanned on
its own terms; virtio discovery was handed only the drive roots, and the images
directory lies five levels below ``D:\`` while the scan is breadth-limited to
three. No amount of budget reaches it - the directory is never enqueued - so a
correctly staged medium was invisible and provisioning could not run at all
without the operator naming the file by hand.

These gates build a real directory tree with that exact geometry and drive the
real discovery over it. The decoy in the general root is larger than the staged
medium, so an implementation that merely merged the two root sets and sorted by
size would return the wrong file rather than pass.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.config import get_project_root
from scripts.sandbox.provision_windows_guest import (
    ProvisioningError,
    discover_virtio_media,
    require_virtio_media,
)


_PROVISIONER: Final[Path] = Path(get_project_root(), "scripts", "sandbox", "provision_windows_guest.py")

_STAGED_ISO_NAME: Final[str] = "virtio-win-0.1.285.iso"
"""Name of the medium as it is staged in the Intellicrack images directory."""

_DECOY_ISO_NAME: Final[str] = "virtio-win-decoy.iso"
"""A shallower medium, deliberately larger, that must not win over the staged one."""

_STAGED_ISO_BYTES: Final[bytes] = b"staged"
_DECOY_ISO_BYTES: Final[bytes] = b"decoy that is measurably larger than the staged medium"

_SCAN_BUDGET: Final[int] = 20_000
"""Generous enough that budget exhaustion can never be what makes a scan fail."""


def _production_int(name: str) -> int:
    """Read an integer constant from the provisioner without importing a private name.

    Args:
        name: Module-level constant to read.

    Returns:
        int: The value the provisioner assigns to it.

    Raises:
        AssertionError: If the provisioner has no such integer constant.
    """
    module = ast.parse(_PROVISIONER.read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        if node.target.id == name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
            return node.value.value
    message = f"{_PROVISIONER.name} defines no integer constant named {name}"
    raise AssertionError(message)


_SCAN_DEPTH: Final[int] = _production_int("_DEFAULT_SCAN_DEPTH")
"""The breadth limit the provisioner really scans drive roots with."""


@pytest.fixture
def staged_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    r"""Build a drive root whose images directory is below the scan depth.

    The nesting reproduces ``<drive>\\Intellicrack\\tools\\qemu\\images``: one
    level deeper than the production scan can reach, whatever that limit is set
    to.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        tuple[Path, Path, Path]: The drive root, the images directory, and the
        staged virtio medium inside it.
    """
    drive_root = tmp_path / "drive"
    images_dir = drive_root
    for level in range(_SCAN_DEPTH + 1):
        images_dir /= f"level{level}"
    images_dir.mkdir(parents=True)

    staged = images_dir / _STAGED_ISO_NAME
    staged.write_bytes(_STAGED_ISO_BYTES)
    return (drive_root, images_dir, staged)


def test_a_medium_staged_in_the_images_directory_is_out_of_reach_of_a_drive_scan(
    staged_layout: tuple[Path, Path, Path],
) -> None:
    """The general scan cannot see the staged medium, and the priority root can.

    The first assertion is the precondition that makes this defect real: if the
    breadth-limited scan could reach the images directory on its own, nothing
    here would be worth fixing.

    Args:
        staged_layout: Drive root, images directory, and the staged medium.
    """
    drive_root, images_dir, staged = staged_layout

    by_drive_scan = discover_virtio_media((drive_root,), _SCAN_DEPTH, _SCAN_BUDGET)
    by_priority_root = discover_virtio_media((drive_root,), _SCAN_DEPTH, _SCAN_BUDGET, priority_roots=(images_dir,))

    assert by_drive_scan is None, (
        f"the depth-{_SCAN_DEPTH} scan reached {staged}, so this tree does not reproduce the geometry that hid the real medium"
    )
    assert by_priority_root == staged, (
        f"discovery returned {by_priority_root} instead of the medium staged in the images directory; "
        f"provisioning fails on a host that has the ISO exactly where it belongs"
    )


def test_the_staged_medium_wins_over_a_shallower_one(staged_layout: tuple[Path, Path, Path]) -> None:
    """Priority roots are searched first, not merged into the general scan.

    The decoy is larger, and the general scan returns its candidates largest
    first, so a merged search would return the decoy.

    Args:
        staged_layout: Drive root, images directory, and the staged medium.
    """
    drive_root, images_dir, staged = staged_layout
    decoy = drive_root / _DECOY_ISO_NAME
    decoy.write_bytes(_DECOY_ISO_BYTES)

    found = discover_virtio_media((drive_root,), _SCAN_DEPTH, _SCAN_BUDGET, priority_roots=(images_dir,))

    assert decoy.stat().st_size > staged.stat().st_size, "the decoy is not larger, so this run cannot detect a merged search"
    assert found == staged, f"discovery preferred {found}; the staged medium must be chosen over anything else on the host"


def test_provisioning_refuses_only_when_the_medium_is_genuinely_absent(staged_layout: tuple[Path, Path, Path]) -> None:
    """The hard-prerequisite error must not fire for a correctly staged medium.

    Args:
        staged_layout: Drive root, images directory, and the staged medium.
    """
    drive_root, images_dir, staged = staged_layout

    resolved = require_virtio_media(None, (drive_root,), _SCAN_DEPTH, _SCAN_BUDGET, priority_roots=(images_dir,))
    assert resolved == staged, f"resolution returned {resolved} rather than the staged medium"

    with pytest.raises(ProvisioningError, match="virtio-win driver ISO not found on this host"):
        require_virtio_media(None, (drive_root,), _SCAN_DEPTH, _SCAN_BUDGET, priority_roots=(drive_root / "absent",))


def test_the_provisioner_searches_its_own_images_directory_for_the_medium() -> None:
    """The images directory must actually be handed to virtio resolution.

    Discovery accepting a priority root is worth nothing if the caller never
    supplies one, which is exactly the state the live run failed in. This reads
    the call the provisioner really makes. ``provision`` resolves the medium's
    path through :func:`~scripts.sandbox.provision_windows_guest.require_virtio_media`
    rather than :func:`~scripts.sandbox.provision_windows_guest.resolve_virtio_medium`
    now, so that the medium is mounted once - held across verification and
    staging - instead of the latter's own separate mount; the priority-root
    contract this gate protects is unchanged.

    Raises:
        AssertionError: If ``provision`` does not resolve the virtio medium.
    """
    module = ast.parse(_PROVISIONER.read_text(encoding="utf-8"))
    calls = [
        node
        for definition in module.body
        if isinstance(definition, ast.FunctionDef) and definition.name == "provision"
        for node in ast.walk(definition)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "require_virtio_media"
    ]
    if not calls:
        message = "provision() no longer resolves a virtio medium at all"
        raise AssertionError(message)

    supplied = [ast.unparse(keyword.value) for call in calls for keyword in call.keywords if keyword.arg == "priority_roots"]
    assert supplied, "provision() resolves the virtio medium without a priority root, so a staged medium stays invisible"
    assert all("images_dir" in expression for expression in supplied), (
        f"provision() passes {supplied} as the priority root rather than its images directory"
    )
