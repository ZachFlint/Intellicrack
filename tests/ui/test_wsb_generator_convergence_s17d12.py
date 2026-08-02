# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D12 (dialog half): the sandbox test must build the same document.

``SandboxTestWorker._generate_wsb_config`` used to concatenate the ``.wsb``
document by hand::

    config_lines = ["<Configuration>", "  <VGpu>Enable</VGpu>"]
    ...
    (f"      <HostFolder>{shared_path}</HostFolder>",)

Two defects followed from that. It emitted ``<VGpu>``, while the backend - the
generator verified to boot a real guest - emits ``<vGPU>``; Windows Sandbox
accepts only one spelling, so the dialog's test configuration did not describe
the same machine the product actually creates. And the host folder was
interpolated raw, so a perfectly legal Windows directory name containing ``&``
produced a document no XML parser will accept.

Both call sites now build through :func:`intellicrack.sandbox.wsb.build_wsb_configuration`.
These gates drive the real worker method and cross-check it against the real
backend method.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import defusedxml.ElementTree as DefusedET

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox
from intellicrack.sandbox.wsb import WSB_VGPU_ELEMENT
from intellicrack.ui.sandbox_config import SandboxTestWorker


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_ACCEPTED_VGPU_SPELLING = "vGPU"
_WRONG_VGPU_SPELLING = "VGpu"
_AMPERSAND_DIR_NAME = "loot & samples"


def _generate(worker: SandboxTestWorker) -> str:
    """Invoke the worker's protected ``.wsb`` generator.

    Args:
        worker: Worker under test.

    Returns:
        str: The generated ``.wsb`` document text.
    """
    generate = cast("Callable[[], str]", getattr(worker, "_generate_wsb_config"))
    return generate()


def _backend_document(tmp_path: Path, *, video_enabled: bool) -> str:
    """Produce the backend's ``.wsb`` document for comparison.

    Args:
        tmp_path: Pytest temporary directory fixture.
        video_enabled: Value for ``SandboxConfig.video_enabled``.

    Returns:
        str: The document ``WindowsSandbox`` writes for that configuration.
    """
    config = SandboxConfig(memory_limit_mb=2048, network_enabled=False, video_enabled=video_enabled, shared_folders=[])
    sandbox = WindowsSandbox(config=config)
    wsb_file = tmp_path / "backend.wsb"
    shared_folder = tmp_path / "backend-shared"
    shared_folder.mkdir()
    setattr(sandbox, "_wsb_path", wsb_file)
    setattr(sandbox, "_shared_folder", shared_folder)
    generate = getattr(sandbox, "_generate_wsb_config")
    asyncio.run(generate())
    return wsb_file.read_bytes().decode("utf-8")


class TestWorkerDocumentSpelling:
    """The dialog's test configuration must use the accepted element spelling."""

    def test_worker_emits_the_accepted_vgpu_spelling(self) -> None:
        """The worker document contains ``vGPU`` and never ``VGpu``."""
        worker = SandboxTestWorker(network_enabled=False, memory_limit_mb=2048)
        document = _generate(worker)

        assert f"<{_ACCEPTED_VGPU_SPELLING}>Enable</{_ACCEPTED_VGPU_SPELLING}>" in document, (
            f"expected the accepted vGPU spelling in:\n{document}"
        )
        assert _WRONG_VGPU_SPELLING not in document, f"the rejected spelling must not survive:\n{document}"
        assert WSB_VGPU_ELEMENT == _ACCEPTED_VGPU_SPELLING, "the shared generator must export the accepted spelling"

    def test_worker_and_backend_agree_on_the_gpu_element(self, tmp_path: Path) -> None:
        """Both generators name the GPU toggle identically for the same request.

        This is the convergence itself: the two documents may differ in the
        options they carry, but a tag present in both must be spelled the same.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        worker = SandboxTestWorker(network_enabled=False, memory_limit_mb=2048)
        worker_root = DefusedET.fromstring(_generate(worker))
        backend_root = DefusedET.fromstring(_backend_document(tmp_path, video_enabled=True))

        worker_gpu = [child.tag for child in worker_root if child.tag.lower() == "vgpu"]
        backend_gpu = [child.tag for child in backend_root if child.tag.lower() == "vgpu"]

        assert worker_gpu == [_ACCEPTED_VGPU_SPELLING], f"worker emitted {worker_gpu!r}"
        assert backend_gpu == [_ACCEPTED_VGPU_SPELLING], f"backend emitted {backend_gpu!r}"
        assert worker_gpu == backend_gpu, "the two generators must not disagree on element spelling"

    def test_worker_document_carries_the_requested_options(self, tmp_path: Path) -> None:
        """Constructor arguments reach the document with their real values.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        shared = tmp_path / "plain"
        shared.mkdir()
        worker = SandboxTestWorker(
            network_enabled=True,
            memory_limit_mb=3072,
            shared_folder=str(shared),
            read_only=True,
        )
        root = DefusedET.fromstring(_generate(worker))

        assert root.findtext("Networking") == "Enable"
        assert root.findtext("MemoryInMB") == "3072"
        assert root.findtext("MappedFolders/MappedFolder/HostFolder") == str(shared)
        assert root.findtext("MappedFolders/MappedFolder/SandboxFolder") == r"C:\Shared"
        assert root.findtext("MappedFolders/MappedFolder/ReadOnly") == "true"
        command = root.findtext("LogonCommand/Command")
        assert command is not None
        assert "&&" in command, f"the chained test command must survive round-tripping; got {command!r}"


class TestWorkerDocumentEscaping:
    """A legal Windows folder name must not break the document."""

    def test_shared_folder_with_ampersand_roundtrips(self, tmp_path: Path) -> None:
        """A real directory named with ``&`` parses back to the same path.

        ``&`` is legal in a Windows directory name, so this is an ordinary user
        folder - and raw interpolation of it yields unparseable XML.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        shared = tmp_path / _AMPERSAND_DIR_NAME
        shared.mkdir()
        worker = SandboxTestWorker(network_enabled=False, memory_limit_mb=2048, shared_folder=str(shared))

        document = _generate(worker)
        assert "&amp;" in document, f"the ampersand must be escaped in:\n{document}"

        root = DefusedET.fromstring(document)
        assert root.findtext("MappedFolders/MappedFolder/HostFolder") == str(shared)

    def test_missing_shared_folder_is_not_mapped(self, tmp_path: Path) -> None:
        """A shared folder that does not exist yields no mapping at all.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        worker = SandboxTestWorker(
            network_enabled=False,
            memory_limit_mb=2048,
            shared_folder=str(tmp_path / "absent"),
        )
        root = DefusedET.fromstring(_generate(worker))
        assert root.find("MappedFolders") is None
