# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the x64dbg bridge plugin deploy/build path and fail-fast load (F16).

These tests exercise the real behaviour that keeps x64dbg control from
silently going inert when the bridge plugin never comes up:

* the arch-to-filename-to-``plugins`` directory mapping used to deploy the
  first-party bridge plugin, driven against a real on-disk x64dbg tree with
  real file copies (no mocks);
* the resolution of the installed x64dbg plugin SDK directory that the source
  rebuild must target;
* the CMake configure invocation passing the SDK path through the variable the
  plugin's ``CMakeLists.txt`` actually reads (``X64DBG_SDK_PATH``);
* the named-pipe client being pointed at the fixed pipe the C++ plugin serves;
* :meth:`X64DbgBridge.load` surfacing the actionable remediation error at load
  time when the bridge pipe never becomes usable, instead of deferring the
  failure to the first debugger RPC such as ``step_into``.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges import (
    installer as installer_module,
    x64dbg as x64dbg_module,
)
from intellicrack.bridges.installer import (
    PLUGIN_ARCHS,
    deploy_x64dbg_plugin_detailed,
    resolve_x64dbg_sdk_path,
)
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.bridges.named_pipe_client import EventHandler, PipeConfig


def _make_plugin_source_tree(source_root: Path) -> dict[str, bytes]:
    """Create a realistic ``x64dbg-plugin/bin`` tree with distinct binaries.

    Writes a unique byte payload for every arch registered in
    :data:`PLUGIN_ARCHS` so a later copy can be verified byte-for-byte
    (a genuine file copy, not a mock).

    Args:
        source_root: Root directory that will contain the
            ``x64dbg-plugin`` source folder.

    Returns:
        dict[str, bytes]: Mapping of plugin filename to the exact bytes
        written for it.
    """
    bin_dir = source_root / "x64dbg-plugin" / "bin"
    bin_dir.mkdir(parents=True)
    payloads: dict[str, bytes] = {}
    for arch, filename, _subdir in PLUGIN_ARCHS:
        payload = f"MZ-intellicrack-bridge-{arch}-{uuid.uuid4().hex}".encode()
        (bin_dir / filename).write_bytes(payload)
        payloads[filename] = payload
    return payloads


class TestDeployArchMapping:
    """Deployment lands each arch's binary in the correct ``plugins`` directory."""

    @staticmethod
    def test_each_arch_binary_copied_to_its_plugins_dir(tmp_path: Path) -> None:
        """Every arch's ``.dp64``/``.dp32`` copies to ``release/<arch>/plugins``.

        Uses a real source tree and a real x64dbg installation directory
        outside Program Files (so no elevation gate trips) and asserts the
        deployed bytes exactly match the source, proving a genuine copy.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        source_root = tmp_path / "src"
        x64dbg_path = tmp_path / "x64dbg_install"
        x64dbg_path.mkdir()
        payloads = _make_plugin_source_tree(source_root)

        result = deploy_x64dbg_plugin_detailed(x64dbg_path, source_root=source_root)

        assert result.success is True
        assert {r.arch for r in result.per_arch} == {arch for arch, _f, _s in PLUGIN_ARCHS}
        assert all(r.status == "deployed" for r in result.per_arch)

        for arch, filename, subdir in PLUGIN_ARCHS:
            target = x64dbg_path / Path(subdir) / filename
            assert target.is_file(), f"missing deployed plugin for {arch}: {target}"
            assert target.read_bytes() == payloads[filename]
            matching = [r for r in result.per_arch if r.arch == arch]
            assert len(matching) == 1
            assert matching[0].target == target

    @staticmethod
    def test_arch_mapping_targets_are_arch_specific(tmp_path: Path) -> None:
        """The x64 binary must not land in the x32 ``plugins`` dir (or vice versa).

        Guards against a regression that swaps the arch-to-subdirectory
        mapping in :data:`PLUGIN_ARCHS`.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        source_root = tmp_path / "src"
        x64dbg_path = tmp_path / "x64dbg_install"
        x64dbg_path.mkdir()
        _make_plugin_source_tree(source_root)

        deploy_x64dbg_plugin_detailed(x64dbg_path, source_root=source_root)

        x64_entry = next(e for e in PLUGIN_ARCHS if e[0] == "x64")
        x32_entry = next(e for e in PLUGIN_ARCHS if e[0] == "x32")

        assert (x64dbg_path / "release" / "x64" / "plugins" / x64_entry[1]).is_file()
        assert (x64dbg_path / "release" / "x32" / "plugins" / x32_entry[1]).is_file()
        # The 64-bit binary must not have been written under the 32-bit tree.
        assert not (x64dbg_path / "release" / "x32" / "plugins" / x64_entry[1]).exists()
        assert not (x64dbg_path / "release" / "x64" / "plugins" / x32_entry[1]).exists()


class TestResolveSdkPath:
    """The installed x64dbg plugin SDK directory is located by its headers."""

    @staticmethod
    def test_resolves_top_level_pluginsdk(tmp_path: Path) -> None:
        """A ``<install>/pluginsdk/bridgemain.h`` layout resolves to that dir.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        sdk = tmp_path / "pluginsdk"
        sdk.mkdir()
        (sdk / "bridgemain.h").write_text("// header", encoding="utf-8")

        assert resolve_x64dbg_sdk_path(tmp_path) == sdk

    @staticmethod
    def test_resolves_release_pluginsdk(tmp_path: Path) -> None:
        """A ``<install>/release/pluginsdk`` layout resolves as a fallback.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        sdk = tmp_path / "release" / "pluginsdk"
        sdk.mkdir(parents=True)
        (sdk / "bridgemain.h").write_text("// header", encoding="utf-8")

        assert resolve_x64dbg_sdk_path(tmp_path) == sdk

    @staticmethod
    def test_rejects_pluginsdk_without_headers(tmp_path: Path) -> None:
        """A ``pluginsdk`` folder missing ``bridgemain.h`` is not accepted.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        (tmp_path / "pluginsdk").mkdir()

        assert resolve_x64dbg_sdk_path(tmp_path) is None


class TestBuildInvocationSdkVariable:
    """The source rebuild passes the SDK path via the CMake variable CMakeLists reads."""

    @staticmethod
    def test_configure_passes_x64dbg_sdk_path_not_x64dbg_path(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """CMake configure carries ``-DX64DBG_SDK_PATH`` and never ``-DX64DBG_PATH``.

        The plugin's ``CMakeLists.txt`` reads ``X64DBG_SDK_PATH``; the old
        invocation passed the dead ``X64DBG_PATH`` flag, so the installed
        build's SDK was silently ignored. This gate captures the real
        argument list handed to the cmake step.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: Per-test temp directory provided by pytest.
        """
        plugin_dir = tmp_path / "x64dbg-plugin"
        plugin_dir.mkdir()
        x64dbg_path = tmp_path / "x64dbg_install"
        sdk = x64dbg_path / "pluginsdk"
        sdk.mkdir(parents=True)
        (sdk / "bridgemain.h").write_text("// header", encoding="utf-8")

        def fake_cmake() -> Path:
            return tmp_path / "cmake.exe"

        def fake_generator(_cmake: Path) -> str:
            return "Visual Studio 18 2026"

        monkeypatch.setattr(installer_module, "_find_cmake", fake_cmake)
        monkeypatch.setattr(installer_module, "_detect_vs_generator", fake_generator)

        configure_cmds: list[list[str]] = []

        def fake_step(cmd: list[str], *, cwd: Path, timeout_s: int, arch: str, phase: str) -> bool:
            del cwd, timeout_s, arch
            if phase == "configure":
                configure_cmds.append(list(cmd))
            return True

        monkeypatch.setattr(installer_module, "_run_cmake_step", fake_step)

        built = installer_module.build_x64dbg_plugin(plugin_dir, x64dbg_path)

        assert built is True
        assert configure_cmds, "no cmake configure step was invoked"
        for cmd in configure_cmds:
            assert any(arg == f"-DX64DBG_SDK_PATH={sdk}" for arg in cmd), cmd
            assert not any(arg.startswith("-DX64DBG_PATH=") for arg in cmd), cmd

    @staticmethod
    def test_build_skipped_when_sdk_missing(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """With no SDK under the install, the build bails before any cmake step.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: Per-test temp directory provided by pytest.
        """
        plugin_dir = tmp_path / "x64dbg-plugin"
        plugin_dir.mkdir()
        x64dbg_path = tmp_path / "x64dbg_install"
        x64dbg_path.mkdir()

        def fake_cmake() -> Path:
            return tmp_path / "cmake.exe"

        def fake_generator(_cmake: Path) -> str:
            return "Visual Studio 18 2026"

        monkeypatch.setattr(installer_module, "_find_cmake", fake_cmake)
        monkeypatch.setattr(installer_module, "_detect_vs_generator", fake_generator)

        step_called = False

        def fake_step(*_args: object, **_kwargs: object) -> bool:
            nonlocal step_called
            step_called = True
            return True

        monkeypatch.setattr(installer_module, "_run_cmake_step", fake_step)

        assert installer_module.build_x64dbg_plugin(plugin_dir, x64dbg_path) is False
        assert step_called is False


class _RecordingPipe:
    """Fake ``NamedPipeClient`` capturing the config it was constructed with."""

    def __init__(self, config: PipeConfig, event_handler: EventHandler | None = None) -> None:
        """Record the pipe configuration and event handler.

        Args:
            config: The :class:`PipeConfig` passed by the bridge.
            event_handler: Optional event handler passed by the bridge.
        """
        self.config = config
        self.event_handler = event_handler

    async def connect(self) -> None:
        """No-op stand-in for the real Win32 connect."""
        await asyncio.sleep(0)

    def set_event_handler(self, handler: EventHandler | None) -> None:
        """Record a later event-handler assignment.

        Args:
            handler: Handler supplied by the bridge after connecting.
        """
        self.event_handler = handler

    @property
    def is_connected(self) -> bool:
        """Report as connected once constructed.

        Returns:
            bool: Always ``True``.
        """
        return True


class TestConnectUsesPluginPipeName:
    """``_connect`` targets the fixed pipe the C++ plugin actually serves."""

    @staticmethod
    def test_connect_config_pipe_name_matches_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
        """The client's pipe name equals the bridge's fixed ``_PIPE_NAME``.

        The plugin's ``pipe_server`` publishes a single fixed endpoint, so a
        per-process default name would never connect. This gate fails if the
        client is reverted to the default :class:`PipeConfig` name.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        captured: dict[str, _RecordingPipe] = {}

        def fake_client(config: PipeConfig, event_handler: EventHandler | None = None) -> _RecordingPipe:
            pipe = _RecordingPipe(config, event_handler)
            captured["pipe"] = pipe
            return pipe

        monkeypatch.setattr(x64dbg_module, "NamedPipeClient", fake_client)

        bridge = X64DbgBridge()

        connect = getattr(bridge, "_connect")
        asyncio.run(connect())

        pipe = captured["pipe"]
        expected_name = getattr(bridge, "_PIPE_NAME")
        assert pipe.config.pipe_name == expected_name
        assert pipe.config.pipe_name == r"\\.\pipe\intellicrack_x64dbg"


class _DummyProcess:
    """Stand-in for :class:`DesktopProcess` returned by ``spawn_on_hidden_desktop``."""

    def __init__(self, pid: int) -> None:
        """Store a unique fake PID.

        Args:
            pid: Fake process id used as the tracking key.
        """
        self.pid = pid

    def terminate(self) -> None:
        """No-op terminate for cleanup callbacks."""

    def wait(self, timeout: float | None = None) -> int:
        """Return a fake exit code.

        Args:
            timeout: Ignored wait timeout.

        Returns:
            int: Always ``0``.
        """
        del timeout
        return 0

    def kill(self) -> None:
        """No-op kill for cleanup callbacks."""

    def close(self) -> None:
        """No-op close, mirroring ``DesktopProcess.close``."""


class _FakeExternalProcessManager:
    """In-process stand-in for ``ProcessManager`` external-PID bookkeeping.

    The real ``register_external_pid`` verifies the PID corresponds to a
    live OS process before recording it, which the synthetic PID from
    :func:`unique_pid` cannot satisfy. This fake mirrors the
    ``register_external_pid``/``unregister_external_pid`` surface
    :class:`X64DbgBridge` now calls after its migration from
    ``subprocess.Popen`` to ``spawn_on_hidden_desktop`` so ``load`` can run
    its real launch path without touching the real singleton.
    """

    def register_external_pid(
        self,
        pid: int,
        name: str,
        process_type: object = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """Accept the registration unconditionally.

        Args:
            pid: Process id to register.
            name: Human-readable process name.
            process_type: The tracked ``ProcessType``.
            metadata: Optional metadata dict.
        """
        del pid, name, process_type, metadata

    def unregister_external_pid(self, pid: int) -> bool:
        """Accept the unregistration unconditionally.

        Args:
            pid: Process id to unregister.

        Returns:
            bool: Always ``True``.
        """
        del pid
        return True


@pytest.fixture
def unique_pid() -> Iterator[int]:
    """Yield a unique fake PID and unregister it from the singleton afterward.

    Yields:
        int: A fake process id guaranteed not to collide with a real one.
    """
    pid = 0x7F000000 + (uuid.uuid4().int & 0xFFFF)
    yield pid
    ProcessManager.get_instance().unregister_external_pid(pid)


class TestLoadFailsFastWhenPipeNeverReady:
    """``load`` raises the actionable remediation error before issuing any RPC."""

    @staticmethod
    def test_load_raises_remediation_before_any_command(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        unique_pid: int,
    ) -> None:
        """A never-ready pipe makes ``load`` fail at load with remediation text.

        Drives ``load`` against a real PE (the running Python executable) with
        a real x64dbg.exe placeholder present and the plugin marked deployed,
        but points the readiness poll at a pipe name that can never exist. The
        failure must surface from ``load`` with the plugin/SDK/Plugins-menu
        remediation guidance, and ``_send_command`` must never be reached -
        proving the failure is not deferred to the first debugger RPC.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: Per-test temp directory provided by pytest.
            unique_pid: Unique fake PID from the fixture.
        """
        if sys.platform != "win32":
            pytest.skip("named-pipe readiness poll is Windows-only")

        bridge = X64DbgBridge()
        setattr(bridge, "_x64dbg_path", tmp_path)
        setattr(bridge, "_plugin_deployed", True)
        exe_dir = tmp_path / "release" / "x64"
        exe_dir.mkdir(parents=True)
        (exe_dir / "x64dbg.exe").write_bytes(b"MZ")

        def fake_spawn(*_args: object, **_kwargs: object) -> _DummyProcess:
            return _DummyProcess(unique_pid)

        fake_manager = _FakeExternalProcessManager()

        def _stub_get_instance(_cls: type[ProcessManager]) -> _FakeExternalProcessManager:
            return fake_manager

        monkeypatch.setattr(x64dbg_module, "_IS_WIN32", True)
        monkeypatch.setattr(x64dbg_module, "spawn_on_hidden_desktop", fake_spawn)
        monkeypatch.setattr(
            x64dbg_module.ProcessManager,
            "get_instance",
            classmethod(_stub_get_instance),
        )
        monkeypatch.setattr(
            X64DbgBridge,
            "_PIPE_NAME",
            rf"\\.\pipe\intellicrack_x64dbg_failfast_{uuid.uuid4().hex}",
        )
        monkeypatch.setattr(X64DbgBridge, "_PIPE_READY_TIMEOUT_SECONDS", 0.3)
        monkeypatch.setattr(X64DbgBridge, "_PIPE_READY_POLL_MS", 50)

        command_reached: dict[str, bool] = {"called": False}

        async def guard_send_command(_self: X64DbgBridge, _command: str) -> str:
            command_reached["called"] = True
            await asyncio.sleep(0)
            return ""

        monkeypatch.setattr(X64DbgBridge, "_send_command", guard_send_command)

        with pytest.raises(ToolError) as exc_info:
            asyncio.run(bridge.load(Path(sys.executable)))

        message = str(exc_info.value)
        assert "bridge plugin" in message
        assert "Plugins menu" in message
        assert "pluginsdk" in message
        assert exc_info.value.details.get("x64dbg_error_code") == "pipe_disconnected"
        assert command_reached["called"] is False
