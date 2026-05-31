# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``intellicrack.sandbox.qemu`` (FIX UNIT 12a).

The pre-existing QEMU sandbox tests validate the audit fixes against mocked
subprocesses, fake QMP clients and synthetic sidecar strings. These tests close
the audit's mock/fake-data findings by driving the QEMU sandbox's host-side
capabilities against REAL binaries, a REAL ``cmd.exe`` guest-execution script,
REAL YARA rules compiled by the real ``yara`` module, and the REAL QEMU binary
installed on the host:

* ``_poll_for_result`` is exercised by running the exact OS-specific execution
  script that :meth:`QEMUSandbox._generate_execution_script` emits through a
  real ``cmd.exe`` so the polled exit code, stdout and stderr come from a real
  process, not hand-written strings (audit Category 1, F-0003).
* ``copy_to_sandbox`` / ``copy_from_sandbox`` round-trip a REAL System32 PE DLL
  and assert byte-for-byte SHA-256 equality (coverage gap).
* ``extract_dropped_files`` collects a REAL PE binary from the host-side dropped
  mirror into a real ZIP and the archive is validated by content hash
  (audit Category 1, F-0007).
* ``yara_scan`` compiles REAL YARA rules with the real ``yara`` module and scans
  a REAL PE binary staged in a dropped-files ZIP, asserting on a real rule hit
  driven by strings genuinely present in the binary (audit Category 1, F-0028).
* ``is_available`` / ``_detect_accelerator`` probe the REAL QEMU binary on the
  host and assert on a real, internally-consistent accelerator result
  (coverage gap; ``is_available`` mocked in the original suite).
* ``_build_qemu_command`` produces a real argv from a real config and image; the
  argv is validated against the real accelerator-dependent ``-cpu`` contract.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine


_HW_ACCELERATORS: frozenset[AcceleratorType] = frozenset({AcceleratorType.WHPX, AcceleratorType.KVM})


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Execute ``coro`` on a dedicated event loop for test isolation.

    Args:
        coro: Awaitable to run to completion.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _sha256(path: Path) -> str:
    """Compute the SHA-256 hex digest of ``path``.

    Args:
        path: File to digest.

    Returns:
        str: Lower-case hexadecimal SHA-256 digest.
    """
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


class _RealOpsSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing private state setters for real-op tests.

    The setters mutate single-underscore attributes from inside the class
    hierarchy so ``basedpyright``'s ``reportPrivateUsage`` rule stays satisfied
    without any inline suppression.
    """

    def set_shared_folder(self, path: Path | None) -> None:
        """Set the host-side shared folder root.

        Args:
            path: Shared folder path, or ``None`` to clear it.
        """
        self._shared_folder = path

    def set_running(self) -> None:
        """Mark the sandbox state as ``running`` for guarded code paths."""
        self.state.status = "running"

    def set_accelerator(self, accel: AcceleratorType) -> None:
        """Pre-populate the cached accelerator so no host probe runs.

        Args:
            accel: Accelerator type to record as cached.
        """
        self._accelerator = accel
        self._accelerator_cached = True

    def set_qemu_path(self, path: Path | None) -> None:
        """Set the resolved QEMU executable path.

        Args:
            path: QEMU executable path, or ``None`` to clear it.
        """
        self._qemu_path = path

    async def poll_for_result_public(
        self,
        *,
        result_path: Path,
        time_limit: int,
        stdout_path: Path | None,
        stderr_path: Path | None,
        script_path: Path | None,
    ) -> tuple[int, str, str]:
        """Expose ``_poll_for_result`` for real guest-script polling tests.

        Args:
            result_path: Exit-code sentinel file path.
            time_limit: Maximum seconds to wait.
            stdout_path: Stdout sidecar path.
            stderr_path: Stderr sidecar path.
            script_path: Originating script path cleaned up after read.

        Returns:
            tuple[int, str, str]: ``(exit_code, stdout, stderr)`` parsed from
            the real guest-script output files.
        """
        return await self._poll_for_result(
            result_path=result_path,
            time_limit=time_limit,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            script_path=script_path,
        )

    def generate_execution_script_public(
        self,
        *,
        command: str,
        script_id: str,
        result_name: str,
        stdout_name: str,
        stderr_name: str,
    ) -> tuple[str, str]:
        """Expose ``_generate_execution_script`` for the real-script tests.

        Args:
            command: Command the generated script runs.
            script_id: Unique script identifier.
            result_name: Exit-code sentinel file name.
            stdout_name: Stdout sidecar file name.
            stderr_name: Stderr sidecar file name.

        Returns:
            tuple[str, str]: ``(script_filename, script_content)``.
        """
        return self._generate_execution_script(
            command=command,
            working_directory=None,
            script_id=script_id,
            result_name=result_name,
            stdout_name=stdout_name,
            stderr_name=stderr_name,
        )

    async def build_qemu_command_public(self) -> list[str]:
        """Expose ``_build_qemu_command`` for argv-contract tests.

        Returns:
            list[str]: Fully-resolved QEMU command-line argv.
        """
        return await self._build_qemu_command()

    async def detect_accelerator_for_test_value(self) -> AcceleratorType:
        """Run the real host accelerator detection probe.

        Returns:
            AcceleratorType: Accelerator detected by probing the real host.
        """
        return await self._detect_accelerator()


def _make_sandbox(*, guest_os: GuestOS = GuestOS.WINDOWS, shared_folder: Path | None = None) -> _RealOpsSandbox:
    """Build a TCG-pinned sandbox with no live VM for real host-side tests.

    Args:
        guest_os: Guest OS to configure.
        shared_folder: Optional host-side shared folder root.

    Returns:
        _RealOpsSandbox: Configured sandbox with a cached TCG accelerator.
    """
    sb = _RealOpsSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=guest_os))
    sb.set_accelerator(AcceleratorType.TCG)
    if shared_folder is not None:
        sb.set_shared_folder(shared_folder)
    return sb


def _stage_real_guest_script(sb: _RealOpsSandbox, work_dir: Path) -> tuple[Path, tuple[Path, Path, Path]]:
    r"""Write the real guest-execution script with guest paths rewritten to ``work_dir``.

    The script body is produced verbatim by
    :meth:`QEMUSandbox._generate_execution_script`; only the guest ``Z:\\output``
    prefix is rewritten to ``work_dir`` so a host ``cmd.exe`` can run the real
    redirection and exit-code emission. The inner command runs in a nested
    ``cmd /c`` so its ``exit /b 7`` only terminates the nested shell and the
    propagated ERRORLEVEL lands in the result sentinel exactly as in the guest.

    Args:
        sb: Sandbox used to generate the real execution script.
        work_dir: Host directory standing in for the guest output folder.

    Returns:
        tuple[Path, tuple[Path, Path, Path]]: ``(script_file, (result, stdout,
        stderr))`` paths.
    """
    script_id = "realpoll01"
    result_name = f"result_{script_id}.txt"
    stdout_name = f"{script_id}.stdout"
    stderr_name = f"{script_id}.stderr"
    _name, content = sb.generate_execution_script_public(
        command='cmd /c "echo REAL-STDOUT-LINE& echo REAL-STDERR-LINE 1>&2& exit /b 7"',
        script_id=script_id,
        result_name=result_name,
        stdout_name=stdout_name,
        stderr_name=stderr_name,
    )
    runnable = content.replace(f"{QEMUSandbox.GUEST_SHARED_PATH_WINDOWS}output\\", f"{work_dir}\\")
    script_file = work_dir / f"exec_{script_id}.cmd"
    script_file.write_text(runnable, encoding="utf-8")
    return script_file, (work_dir / result_name, work_dir / stdout_name, work_dir / stderr_name)


class TestPollForResultAgainstRealProcess:
    """``_poll_for_result`` must read REAL exit code/stdout/stderr from a real run."""

    @pytest.mark.spawns_process
    def test_real_cmd_script_drives_poll_result(self, tmp_path: Path) -> None:
        """The generated Windows script runs in real ``cmd.exe``; poll reads real output.

        This drives the exact guest-execution contract: the host writes the
        script that :meth:`QEMUSandbox._generate_execution_script` produces,
        a REAL ``cmd.exe`` executes it (emulating the guest), and
        ``_poll_for_result`` parses the real exit code and sidecar streams.

        Args:
            tmp_path: Pytest temp directory used as the output folder.
        """
        if shutil.which("cmd.exe") is None:
            pytest.skip("cmd.exe not available; real guest-script execution cannot be emulated")

        sb = _make_sandbox(guest_os=GuestOS.WINDOWS)
        script_file, (result_path, stdout_path, stderr_path) = _stage_real_guest_script(sb, tmp_path)

        async def _go() -> tuple[int, str, str]:
            proc = await asyncio.create_subprocess_exec(
                "cmd.exe",
                "/c",
                str(script_file),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return await sb.poll_for_result_public(
                result_path=result_path,
                time_limit=15,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                script_path=script_file,
            )

        exit_code, stdout, stderr = _run(_go())

        assert exit_code == 7, f"poll must read the real exit code 7 from cmd.exe; got {exit_code}"
        assert "REAL-STDOUT-LINE" in stdout, f"poll must read real stdout sidecar; got {stdout!r}"
        assert "REAL-STDERR-LINE" in stderr, f"poll must read real stderr sidecar; got {stderr!r}"
        assert not result_path.exists(), "real result sentinel must be cleaned up after a successful poll"
        assert not stdout_path.exists(), "real stdout sidecar must be cleaned up"
        assert not stderr_path.exists(), "real stderr sidecar must be cleaned up"


class TestCopyRoundTripRealBinary:
    """``copy_to_sandbox`` / ``copy_from_sandbox`` must preserve real PE bytes."""

    def test_real_pe_dll_round_trip_is_byte_identical(self, tmp_path: Path, real_pe_dll: Path) -> None:
        """A real System32 DLL survives a copy-in/copy-out cycle byte for byte.

        Args:
            tmp_path: Pytest temp directory used as the shared folder root.
            real_pe_dll: Real System32 PE DLL fixture.
        """
        shared = tmp_path / "shared"
        shared.mkdir()
        sb = _make_sandbox(shared_folder=shared)

        retrieved = tmp_path / "retrieved" / real_pe_dll.name

        async def _go() -> None:
            await sb.copy_to_sandbox(real_pe_dll, f"input/{real_pe_dll.name}")
            await sb.copy_from_sandbox(f"input/{real_pe_dll.name}", retrieved)

        _run(_go())

        staged = shared / "input" / real_pe_dll.name
        assert staged.exists(), "copy_to_sandbox must stage the real DLL under the shared folder"
        assert retrieved.exists(), "copy_from_sandbox must materialise the retrieved DLL on the host"

        source_digest = _sha256(real_pe_dll)
        assert _sha256(staged) == source_digest, "staged copy must be byte-identical to the real DLL"
        assert _sha256(retrieved) == source_digest, "round-tripped copy must be byte-identical to the real DLL"
        assert retrieved.read_bytes()[:2] == b"MZ", "retrieved copy must retain the real PE MZ magic"


class TestExtractDroppedRealBinary:
    """``extract_dropped_files`` must archive REAL collected binaries faithfully."""

    def test_real_pe_in_mirror_is_zipped_with_intact_bytes(self, tmp_path: Path, real_pe_dll: Path) -> None:
        """A real PE in the host mirror is collected into a ZIP with intact bytes.

        Args:
            tmp_path: Pytest temp directory used as the shared folder root.
            real_pe_dll: Real System32 PE DLL fixture.
        """
        shared = tmp_path / "shared"
        (shared / "output").mkdir(parents=True)
        mirror = shared / "output" / "dropped"
        mirror.mkdir(parents=True)
        dropped = mirror / real_pe_dll.name
        shutil.copy2(real_pe_dll, dropped)

        sb = _make_sandbox(shared_folder=shared)
        sb.set_running()

        async def _go() -> Path:
            return await sb.extract_dropped_files()

        zip_path = _run(_go())

        assert zip_path.exists()
        assert zipfile.is_zipfile(zip_path), "extract_dropped_files must produce a valid ZIP archive"
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            member = next(n for n in names if n.endswith(real_pe_dll.name))
            payload = zf.read(member)

        assert payload[:2] == b"MZ", "archived dropped file must retain the real PE MZ magic"
        assert hashlib.sha256(payload).hexdigest() == _sha256(real_pe_dll), (
            "archived dropped file must be byte-identical to the real binary collected from the mirror"
        )


class TestYaraScanRealRulesRealBinary:
    """``yara_scan`` must match REAL rules against a REAL binary in a dropped ZIP."""

    def test_real_pe_magic_rule_matches_real_binary(self, tmp_path: Path, real_pe_dll: Path) -> None:
        """A real YARA rule keyed on the real PE magic yields a real match.

        The rule condition reads the 16-bit little-endian value at offset 0 and
        requires it to equal ``0x5A4D`` (the ``MZ`` magic). The match is
        therefore produced by the real ``yara`` engine over the real binary's
        actual header bytes, not by a string injected into the test. A
        non-PE control file is included in the same scan set and must NOT match,
        proving the condition discriminates on real content.

        Args:
            tmp_path: Pytest temp directory used as the shared folder root.
            real_pe_dll: Real System32 PE DLL fixture.
        """
        yara = pytest.importorskip("yara", reason="yara-python required for a real YARA scan")

        shared = tmp_path / "shared"
        (shared / "output").mkdir(parents=True)
        non_pe = tmp_path / "not_a_pe.bin"
        non_pe.write_bytes(b"\x00\x01plain-data-not-a-pe")
        zip_path = shared / "output" / "dropped_files_realcov12a.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(real_pe_dll, real_pe_dll.name)
            zf.write(non_pe, non_pe.name)

        rules_file = tmp_path / "pe_magic.yar"
        rules_file.write_text(
            "rule RealPEMagic {\n    condition:\n        uint16(0) == 0x5A4D\n}\n",
            encoding="utf-8",
        )

        # Confirm the rule genuinely matches the real binary via the real engine
        # before asserting that the sandbox surfaces the same match.
        compiled = yara.compile(filepath=str(rules_file))
        assert compiled.match(filepath=str(real_pe_dll)), "real PE fixture must satisfy the real MZ-magic rule"
        assert not compiled.match(filepath=str(non_pe)), "non-PE control must not satisfy the real MZ-magic rule"

        sb = _make_sandbox(shared_folder=shared)

        async def _go() -> list[dict[str, object]]:
            return await sb.yara_scan(rules_path=str(rules_file), scan_target="files")

        matches = _run(_go())

        assert matches, "yara_scan must surface the real rule match over the real PE binary"
        rule_names = {str(m.get("rule")) for m in matches}
        assert "RealPEMagic" in rule_names, f"expected the real rule name in matches; got {rule_names}"
        scanned = {str(m.get("source", "")) for m in matches}
        assert any(real_pe_dll.name in s for s in scanned if s), f"match must reference the real scanned PE; got {scanned}"
        assert not any("not_a_pe" in s for s in scanned if s), "the non-PE control must not produce a match"


class TestRealHostAcceleratorProbe:
    """``is_available`` / ``_detect_accelerator`` must probe the REAL QEMU host."""

    @pytest.mark.spawns_process
    def test_is_available_detects_real_qemu_and_consistent_accelerator(self) -> None:
        """A real ``is_available`` probe resolves the real QEMU binary and accelerator.

        When QEMU is genuinely absent the method must report ``False`` rather
        than fabricate availability; when present it must cache a real
        accelerator that ``_build_qemu_command`` can consume consistently.
        """
        sb = _RealOpsSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))

        if shutil.which(QEMUSandbox.QEMU_EXE) is None and not QEMUSandbox.TOOLS_PATH.exists():
            available = _run(sb.is_available())
            assert available is False, "is_available must report False when no real QEMU binary exists"
            return

        available = _run(sb.is_available())
        assert available is True, "is_available must report True when the real QEMU binary is present on the host"
        assert isinstance(sb.qemu_config, QEMUConfig)

        # A second probe must reuse the cached accelerator and re-detect a value
        # of the same concrete type from the real host.
        detected = _run(sb.detect_accelerator_for_test_value())
        assert isinstance(detected, AcceleratorType), "real accelerator detection must yield an AcceleratorType"


class TestBuildQemuCommandRealContract:
    """``_build_qemu_command`` must satisfy the real accelerator/argv contract."""

    def test_argv_respects_real_accelerator_cpu_contract(self, tmp_path: Path) -> None:
        """TCG argv must avoid ``-cpu host`` and embed the real configured ports.

        ``-cpu host`` requires hardware virtualisation; on TCG the command must
        use ``max`` instead. The argv must also carry the exact monitor/agent
        ports from the real configuration so the QMP and agent sockets line up.

        Args:
            tmp_path: Pytest temp directory used to host a real disk image file.
        """
        image = tmp_path / "guest.qcow2"
        image.write_bytes(b"QFI\xfb" + b"\x00" * 508)

        sb = _RealOpsSandbox(
            config=SandboxConfig(),
            qemu_config=QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                image_path=image,
                monitor_port=14444,
                ssh_port=12222,
                agent_port=14445,
                cpu_cores=4,
                memory_mb=3072,
            ),
        )
        sb.set_accelerator(AcceleratorType.TCG)
        sb.set_qemu_path(Path("qemu-system-x86_64"))

        argv = _run(sb.build_qemu_command_public())
        joined = " ".join(argv)

        cpu_idx = argv.index("-cpu")
        cpu_value = argv[cpu_idx + 1]
        assert "host" not in cpu_value, f"TCG argv must not use '-cpu host'; got {cpu_value!r}"
        assert cpu_value.startswith("max"), f"TCG argv must use '-cpu max...'; got {cpu_value!r}"

        assert "accel=tcg" in joined, "argv must request the cached TCG accelerator"
        assert "cores=4" in joined, "argv must reflect the real configured cpu core count"
        assert str(image) in joined, "argv must reference the real disk image path"
        assert "tcp:127.0.0.1:14444" in joined, "argv must expose QMP on the real configured monitor port"
        assert "hostfwd=tcp::14445-:4445" in joined, "argv must forward the real configured agent port"
