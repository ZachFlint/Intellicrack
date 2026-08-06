# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D06: the configured QEMU disk image must reach the backend.

Before this fix ``SandboxBridge.create`` had no ``qemu_config`` parameter and
never passed one, so ``SandboxManager.create`` always received ``None`` and the
QEMU backend booted with ``QEMUConfig.image_path is None``. Every QEMU sandbox
creation from the GUI therefore failed inside ``_build_qemu_command``, making
the whole QEMU backend - and with it Snapshots, VM Display, Pause/Continue and
Pending Messages - unreachable from the application on any host.

These tests drive the real chain end to end: a real JSON settings document on
disk, the real settings loader, the real bridge, and the real QEMU command
builder. The final assertion is made against the actual argv the backend would
launch QEMU with, so dropping the configuration anywhere along the chain makes
the disk image vanish from the command line and fails the test.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import (
    ExecutionReport,
    ExecutionResult,
    SandboxConfig,
    SandboxError,
)
from intellicrack.sandbox.manager import SandboxInstance, SandboxManager
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox
from intellicrack.sandbox.settings import (
    QEMU_ACCELERATION_KEY,
    QEMU_AGENT_TIMEOUT_KEY,
    QEMU_CPU_CORES_KEY,
    QEMU_GUEST_OS_KEY,
    QEMU_IMAGE_PATH_KEY,
    QEMU_MEMORY_MB_KEY,
    build_qemu_config,
    load_qemu_config,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from intellicrack.sandbox.manager import SandboxType


_RUN_SUCCEEDED: ExecutionResult = "success"

_EXPECTED_CPU_CORES = 6
_EXPECTED_MEMORY_MB = 8192
_EXPECTED_AGENT_TIMEOUT = 45.0


def _fixed_config_file(target: Path) -> Callable[[str], Path]:
    """Build a ``get_config_file`` replacement resolving to a fixed path.

    Args:
        target: Path every lookup should resolve to.

    Returns:
        Callable[[str], Path]: Resolver returning ``target`` for any filename.
    """

    def _resolve(filename: str) -> Path:
        """Resolve any configuration filename to the fixed target.

        Args:
            filename: Requested configuration filename, ignored.

        Returns:
            Path: The fixed target path.
        """
        del filename
        return target

    return _resolve


def _make_disk_image(tmp_path: Path) -> Path:
    """Create a real, minimal qcow2 file so the command builder accepts it.

    ``_build_qemu_command`` requires the configured image path to exist on
    disk. A valid qcow2 v3 header is written so the fixture is a genuine (if
    empty) qcow2 file rather than arbitrary bytes.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: Path to the created qcow2 image file.
    """
    header = b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64)
    image = tmp_path / "guest.qcow2"
    image.write_bytes(header)
    return image


class _CommandBuildingSandbox(QEMUSandbox):
    """QEMU sandbox exposing the real launch-command builder to tests.

    Attributes:
        executed: Every binary this backend was asked to run, in order.
    """

    executed: list[Path]

    def __init__(self, config: SandboxConfig, qemu_config: QEMUConfig | None) -> None:
        """Initialise the backend with an empty execution log.

        Args:
            config: General sandbox configuration.
            qemu_config: QEMU-specific configuration under test.
        """
        super().__init__(config, qemu_config)
        self.executed = []

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Record the requested execution without booting a guest.

        Only the guest boot is skipped; the configuration this backend was
        constructed from - the thing under test - is untouched.

        Args:
            binary_path: Binary the manager asked to run.
            args: Command line arguments, unused.
            time_limit: Timeout override, unused.
            monitor: Whether behaviour monitoring was requested, unused.

        Returns:
            ExecutionReport: A real, empty-activity report.
        """
        del args, time_limit, monitor
        self.executed.append(binary_path)
        return ExecutionReport(
            result=_RUN_SUCCEEDED,
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
        )

    def prepare(self, qemu_path: Path) -> None:
        """Install a resolved QEMU binary path and accelerator for building.

        Args:
            qemu_path: Path recorded as the resolved QEMU executable.
        """
        self._qemu_path = qemu_path
        self._accelerator = AcceleratorType.TCG
        self._accelerator_cached = True

    def build_command(self) -> list[str]:
        """Build the real QEMU launch argv for the current configuration.

        Returns:
            list[str]: The argv the backend would launch QEMU with.
        """
        return asyncio.run(self._build_qemu_command())


class _BackendBuildingManager(SandboxManager):
    """Manager that builds a real QEMU backend from the forwarded configuration.

    ``SandboxManager.create`` normally probes host availability and boots the
    guest, neither of which can run inside the test container. This subclass
    keeps the part under test real - the ``qemu_config`` handed down by the
    bridge is used to construct a genuine :class:`QEMUSandbox` - and skips only
    the host probe and the VM boot.

    Attributes:
        created_sandbox: The real backend constructed from the forwarded config.
    """

    created_sandbox: _CommandBuildingSandbox | None

    def __init__(self, qemu_path: Path) -> None:
        """Initialise the manager.

        Args:
            qemu_path: Path recorded on built backends as the QEMU executable.
        """
        super().__init__()
        self._qemu_path = qemu_path
        self.created_sandbox = None

    async def create(
        self,
        sandbox_type: SandboxType = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        qemu_config: QEMUConfig | None = None,
        *,
        auto_start: bool = True,
        mark_busy: bool = False,
    ) -> SandboxInstance:
        """Construct a real QEMU backend from the forwarded configuration.

        Args:
            sandbox_type: Type of sandbox to create.
            config: Optional configuration override.
            binary_path: Optional binary to associate.
            qemu_config: QEMU-specific configuration forwarded by the bridge.
            auto_start: Ignored; the guest is never booted in tests.
            mark_busy: Whether the instance is registered as busy.

        Returns:
            SandboxInstance: Instance wrapping the constructed backend.
        """
        del auto_start
        sandbox = _CommandBuildingSandbox(config or SandboxConfig(), qemu_config)
        sandbox.prepare(self._qemu_path)
        self.created_sandbox = sandbox
        instance = SandboxInstance(
            sandbox=sandbox,
            sandbox_type=sandbox_type,
            binary_path=binary_path,
        )
        instance.is_busy = mark_busy
        # Registered exactly as the real create does, and marked running, so
        # the inherited run_binary can genuinely find it: a manager that never
        # registered anything would make the reuse assertion unfalsifiable.
        instance.state.status = "running"
        self._instances[instance.id] = instance
        return instance


def _write_settings(tmp_path: Path, image: Path) -> Path:
    """Write a real sandbox settings document naming the disk image.

    Args:
        tmp_path: Per-test temporary directory.
        image: Disk image the settings should point at.

    Returns:
        Path: Path to the written settings document.
    """
    settings: dict[str, Any] = {
        QEMU_IMAGE_PATH_KEY: str(image),
        QEMU_GUEST_OS_KEY: GuestOS.LINUX.value,
        QEMU_CPU_CORES_KEY: _EXPECTED_CPU_CORES,
        QEMU_MEMORY_MB_KEY: _EXPECTED_MEMORY_MB,
        QEMU_ACCELERATION_KEY: False,
        QEMU_AGENT_TIMEOUT_KEY: _EXPECTED_AGENT_TIMEOUT,
    }
    settings_file = tmp_path / "sandbox.json"
    settings_file.write_text(json.dumps(settings), encoding="utf-8")
    return settings_file


def _drive_argument(cmd: list[str]) -> str:
    """Return the ``-drive`` argument from a QEMU argv.

    Args:
        cmd: Full QEMU argv.

    Returns:
        str: The value following the first ``-drive`` flag.
    """
    assert "-drive" in cmd, f"argv has no -drive flag: {cmd}"
    return cmd[cmd.index("-drive") + 1]


class TestSettingsLoadIntoQemuConfig:
    """The persisted settings document must produce a usable QEMUConfig."""

    def test_build_qemu_config_reads_every_persisted_field(self, tmp_path: Path) -> None:
        """Each QEMU setting written by the dialog reaches the backend config.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _make_disk_image(tmp_path)
        settings_file = _write_settings(tmp_path, image)
        settings: dict[str, Any] = json.loads(settings_file.read_text(encoding="utf-8"))

        cfg = build_qemu_config(settings)

        assert cfg.image_path == image
        assert cfg.guest_os is GuestOS.LINUX
        assert cfg.cpu_cores == _EXPECTED_CPU_CORES
        assert cfg.memory_mb == _EXPECTED_MEMORY_MB
        assert cfg.enable_acceleration is False
        assert cfg.agent_connect_timeout == _EXPECTED_AGENT_TIMEOUT

    def test_load_qemu_config_reads_the_settings_file_on_disk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The loader reads the real settings document from the config dir.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the config file.
        """
        image = _make_disk_image(tmp_path)
        settings_file = _write_settings(tmp_path, image)
        monkeypatch.setattr(
            "intellicrack.sandbox.settings.get_config_file",
            _fixed_config_file(settings_file),
        )

        cfg = load_qemu_config()

        assert cfg.image_path == image

    def test_missing_settings_file_yields_unconfigured_image(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An absent settings document leaves the image unset rather than crashing.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the config file.
        """
        absent = tmp_path / "does-not-exist.json"
        monkeypatch.setattr(
            "intellicrack.sandbox.settings.get_config_file",
            _fixed_config_file(absent),
        )

        assert load_qemu_config().image_path is None

    def test_malformed_settings_file_yields_unconfigured_image(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A corrupt settings document degrades to defaults instead of raising.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the config file.
        """
        broken = tmp_path / "broken.json"
        broken.write_text("{not valid json", encoding="utf-8")
        monkeypatch.setattr(
            "intellicrack.sandbox.settings.get_config_file",
            _fixed_config_file(broken),
        )

        assert load_qemu_config().image_path is None


class TestBridgeForwardsQemuConfig:
    """The bridge must forward ``qemu_config`` down to the QEMU backend."""

    def test_configured_image_appears_in_the_real_launch_argv(self, tmp_path: Path) -> None:
        """A disk image passed to the bridge reaches the real QEMU command line.

        This is the end-to-end S17-D06 gate: bridge -> manager -> backend ->
        argv. If the bridge drops ``qemu_config`` the backend has no image and
        ``_build_qemu_command`` raises instead of producing a ``-drive``.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _make_disk_image(tmp_path)
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        result = asyncio.run(
            bridge.create(
                sandbox_type="qemu",
                qemu_config=QEMUConfig(guest_os=GuestOS.LINUX, image_path=image),
            ),
        )

        assert result["type"] == "qemu"
        sandbox = manager.created_sandbox
        assert sandbox is not None
        assert sandbox.qemu_config.image_path == image

        drive = _drive_argument(sandbox.build_command())
        assert str(image) in drive, f"configured disk image missing from -drive: {drive!r}"

    def test_guest_resources_from_config_reach_the_launch_argv(self, tmp_path: Path) -> None:
        """CPU and memory chosen in settings drive the real QEMU argv.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _make_disk_image(tmp_path)
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        asyncio.run(
            bridge.create(
                sandbox_type="qemu",
                qemu_config=QEMUConfig(
                    guest_os=GuestOS.LINUX,
                    image_path=image,
                    cpu_cores=_EXPECTED_CPU_CORES,
                    memory_mb=_EXPECTED_MEMORY_MB,
                ),
            ),
        )

        sandbox = manager.created_sandbox
        assert sandbox is not None
        cmd = sandbox.build_command()

        assert cmd[cmd.index("-smp") + 1] == f"cores={_EXPECTED_CPU_CORES}"
        assert cmd[cmd.index("-m") + 1] == str(_EXPECTED_MEMORY_MB)

    def test_creating_qemu_without_a_config_still_fails_loudly(self, tmp_path: Path) -> None:
        """Omitting the config leaves no image, and the backend refuses to build.

        Args:
            tmp_path: Per-test temporary directory.
        """
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        asyncio.run(bridge.create(sandbox_type="qemu"))

        sandbox = manager.created_sandbox
        assert sandbox is not None
        assert sandbox.qemu_config.image_path is None

        with pytest.raises(SandboxError):
            sandbox.build_command()


class TestRunBinaryForwardsQemuConfig:
    """S17-D28/D29: the run path must carry the same configuration as create.

    ``SandboxBridge.create`` was given ``qemu_config`` when S17-D06 was fixed,
    but ``run_binary`` was left calling ``SandboxManager.run_binary`` without
    it - and without ``reuse_instance``, which that method has always accepted.
    Found live on 2026-08-05: with a QEMU sandbox running and its guest agent
    answering, "Run in Sandbox" reported *Failed to start sandbox* because the
    run booted a **second** virtual machine and built its command line from a
    default ``QEMUConfig`` whose ``image_path`` is None.

    ``SandboxManager.run_binary`` is the real one here; only the host probe and
    the guest boot are replaced, so what the bridge forwards is what a real
    backend is constructed from.
    """

    def test_configured_image_reaches_the_backend_the_run_creates(self, tmp_path: Path) -> None:
        """A run with no reusable instance still builds a bootable command line.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _make_disk_image(tmp_path)
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        asyncio.run(
            bridge.run_binary(
                str(binary),
                sandbox_type="qemu",
                qemu_config=QEMUConfig(guest_os=GuestOS.LINUX, image_path=image),
            ),
        )

        sandbox = manager.created_sandbox
        assert sandbox is not None
        assert sandbox.qemu_config.image_path == image, "the run path dropped the configured disk image"

        drive = _drive_argument(sandbox.build_command())
        assert str(image) in drive, f"configured disk image missing from -drive: {drive!r}"

    def test_a_running_sandbox_is_reused_instead_of_booting_another(self, tmp_path: Path) -> None:
        """With ``reuse_instance`` the run must land in the existing sandbox.

        The panel always has an instance in front of the user when the Run
        button is enabled, so booting a second virtual machine beside it is
        both wrong and expensive. The gate is that no new backend is built and
        the binary is recorded against the instance that already existed.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _make_disk_image(tmp_path)
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        existing = asyncio.run(
            bridge.create(
                sandbox_type="qemu",
                qemu_config=QEMUConfig(guest_os=GuestOS.LINUX, image_path=image),
            ),
        )
        created_for_the_first_time = manager.created_sandbox

        asyncio.run(
            bridge.run_binary(
                str(binary),
                sandbox_type="qemu",
                qemu_config=QEMUConfig(guest_os=GuestOS.LINUX, image_path=image),
                reuse_instance=True,
            ),
        )

        assert manager.created_sandbox is created_for_the_first_time, (
            "the run booted a second sandbox instead of reusing the one already running"
        )
        reused = asyncio.run(manager.get(str(existing["instance_id"])))
        assert reused is not None
        assert reused.binary_path == binary, f"the reused instance was not given the binary; got {reused.binary_path}"

    def test_a_run_without_the_config_still_cannot_boot(self, tmp_path: Path) -> None:
        """Omitting the config leaves the run's backend with no image.

        This is the state the live failure was in, pinned so the forwarding
        cannot quietly become a default that hides a missing image.

        Args:
            tmp_path: Per-test temporary directory.
        """
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        asyncio.run(bridge.run_binary(str(binary), sandbox_type="qemu"))

        sandbox = manager.created_sandbox
        assert sandbox is not None
        assert sandbox.qemu_config.image_path is None

        with pytest.raises(SandboxError):
            sandbox.build_command()


class TestMissingImageErrorIsActionable:
    """The no-image failure must tell the user how to fix it."""

    def test_unset_image_error_names_the_setting_to_change(self, tmp_path: Path) -> None:
        """The error for an unconfigured image points at the settings dialog.

        Args:
            tmp_path: Per-test temporary directory.
        """
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")

        sandbox = _CommandBuildingSandbox(SandboxConfig(), QEMUConfig(image_path=None))
        sandbox.prepare(qemu_path)

        with pytest.raises(SandboxError) as excinfo:
            sandbox.build_command()

        message = str(excinfo.value)
        assert "disk image" in message.lower()
        assert "sandbox settings" in message.lower(), f"error does not say where to configure the image: {message!r}"

    def test_missing_image_error_names_the_configured_path(self, tmp_path: Path) -> None:
        """The error for a vanished image reports the path that was not found.

        Args:
            tmp_path: Per-test temporary directory.
        """
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")
        absent_image = tmp_path / "deleted.qcow2"

        sandbox = _CommandBuildingSandbox(SandboxConfig(), QEMUConfig(image_path=absent_image))
        sandbox.prepare(qemu_path)

        with pytest.raises(SandboxError) as excinfo:
            sandbox.build_command()

        assert str(absent_image) in str(excinfo.value)


class TestBridgeRejectsUnknownTypes:
    """Adding ``qemu_config`` must not weaken sandbox-type validation."""

    def test_unknown_sandbox_type_is_still_rejected(self, tmp_path: Path) -> None:
        """An invalid type raises before any backend is constructed.

        Args:
            tmp_path: Per-test temporary directory.
        """
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")

        manager = _BackendBuildingManager(qemu_path)
        bridge = SandboxBridge()
        bridge.attach_manager(manager)

        with pytest.raises(ToolError):
            asyncio.run(bridge.create(sandbox_type="Qemu"))

        assert manager.created_sandbox is None
