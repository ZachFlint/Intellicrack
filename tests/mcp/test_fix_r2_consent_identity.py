# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, items 3, 4, 5 and 47: trust and approvals follow what a server can do, and survive concurrent writers.

Every gate drives the real :class:`TrustStore`, :class:`ApprovalStore` and :class:`McpConsentGate` over real files in the test's own
directory. The identity gates for a remote server connect a real :class:`McpConnectionManager` to a real SDK ``MCPServer`` over Streamable
HTTP; the concurrency gates write from real threads and real child processes at once.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QLabel

from intellicrack.core.tools import ToolRegistry
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import (
    HttpServerSpec,
    McpConfigDocument,
    McpConfigStore,
    McpSandboxSpec,
    McpServerConfig,
    McpTransportKind,
    StdioServerSpec,
)
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import (
    ApprovalScope,
    ApprovalStore,
    ConsentAnswer,
    McpConsentGate,
    McpConsentStoreError,
    TrustState,
    TrustStore,
    describe_launch,
    launch_digest,
    server_identity,
)
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import McpToolSource
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from tests._helpers.child_python import run_child_json
from tests._helpers.mcp_http_process import running_server


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot

    from intellicrack.mcp.consent import DangerousPattern


_SERVER_SCRIPT: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_server_main.py"
_WRITERS: Final[int] = 12
_RECORDS_PER_WRITER: Final[int] = 15
_RECORDS_PER_PROCESS: Final[int] = 80
_PROCESSES: Final[int] = 4
_CONNECT_TIMEOUT_S: Final[float] = 60.0


def _stdio(*, sandbox: McpSandboxSpec | None = None, env: dict[str, str] | None = None, env_file: str | None = None) -> McpServerConfig:
    """Build a local server configuration.

    Args:
        sandbox: The sandbox settings.
        env: Inline environment entries.
        env_file: An environment file.

    Returns:
        McpServerConfig: The configuration.
    """
    return McpServerConfig(
        server_id="local",
        kind=McpTransportKind.STDIO,
        stdio=StdioServerSpec(command="npx", args=("-y", "@example/server"), env=env or {}, env_file=env_file),
        enabled=True,
        sandbox=sandbox or McpSandboxSpec(),
    )


def _http(headers: dict[str, str], *, port: int = 1, client_id: str | None = None) -> McpServerConfig:
    """Build a remote server configuration.

    Args:
        headers: Configured request headers.
        port: The loopback port it listens on.
        client_id: A pre-registered OAuth client id.

    Returns:
        McpServerConfig: The configuration.
    """
    return McpServerConfig(
        server_id="remote",
        kind=McpTransportKind.HTTP,
        http=HttpServerSpec(url=f"http://127.0.0.1:{port}/mcp", headers=headers, oauth_client_id=client_id),
        enabled=True,
        request_timeout_s=30.0,
    )


class _RecordingPrompt:
    """A launch prompt that approves and trusts, and counts how often it was asked."""

    def __init__(self) -> None:
        """Start with no questions asked."""
        self.asked: list[str] = []

    def __call__(self, config: McpServerConfig, description: str, findings: list[DangerousPattern]) -> ConsentAnswer:
        """Record the question and approve with trust.

        Args:
            config: The server being launched.
            description: The rendered description.
            findings: Flagged patterns.

        Returns:
            ConsentAnswer: Approved and trusted.
        """
        del config, findings
        self.asked.append(description)
        return ConsentAnswer(approved=True, trusted=True)


_SANDBOXED: Final[McpSandboxSpec] = McpSandboxSpec(enabled=True, allow_write=("C:\\work",))

_WIDENINGS: Final[dict[str, tuple[McpServerConfig, McpServerConfig]]] = {
    "sandbox_disabled": (_stdio(sandbox=_SANDBOXED), _stdio(sandbox=McpSandboxSpec())),
    "allow_write_widened_to_the_drive": (_stdio(sandbox=_SANDBOXED), _stdio(sandbox=replace(_SANDBOXED, allow_write=("C:\\",)))),
    "inherited_variable_added": (_stdio(sandbox=_SANDBOXED), _stdio(sandbox=replace(_SANDBOXED, inherit_env=("USERPROFILE",)))),
    "path_changed": (_stdio(env={"PATH": "C:\\tools"}), _stdio(env={"PATH": "C:\\Users\\Public\\evil"})),
}
"""Configuration changes that widen what a local server reaches, as (before, after)."""


class TestPrivilegeWideningChangesAskAgain:
    """Item 3: every change that widens what a server can reach revokes trust and asks again."""

    @pytest.mark.parametrize("change", sorted(_WIDENINGS))
    def test_local_server_is_asked_about_again(self, tmp_path: Path, change: str) -> None:
        """A trusted local server whose sandbox or environment is widened is untrusted and prompted again.

        Args:
            tmp_path: Per-test directory.
            change: Which widening to apply.
        """
        before, after = _WIDENINGS[change]
        prompt = _RecordingPrompt()
        gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt)
        env = dict(before.stdio.env) if before.stdio is not None else {}
        after_env = dict(after.stdio.env) if after.stdio is not None else {}

        asyncio.run(gate.ensure_launch_consent(before, env))
        gate.set_config_lookup(lambda _server_id: before)
        assert gate.is_trusted("local")

        gate.set_config_lookup(lambda _server_id: after)
        assert not gate.is_trusted("local")
        asyncio.run(gate.ensure_launch_consent(after, after_env))

        assert len(prompt.asked) == 2
        assert server_identity(before) != server_identity(after)

    def test_remote_server_header_change_revokes_trust(self, tmp_path: Path) -> None:
        """A trusted remote server whose headers change is no longer trusted.

        Args:
            tmp_path: Per-test directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        before = _http({"X-Tenant": "alpha"})
        after = _http({"X-Tenant": "beta"})
        trust.set_state("remote", TrustState.TRUSTED, identity=server_identity(before))
        gate = McpConsentGate(trust, _RecordingPrompt())

        assert trust.state_for(before) is TrustState.TRUSTED
        assert trust.state_for(after) is TrustState.UNTRUSTED
        assert gate.note_identity(after) is True
        assert trust.state("remote") is TrustState.UNTRUSTED
        assert trust.identity("remote") == server_identity(after)

    def test_oauth_client_change_changes_identity(self) -> None:
        """Pointing a remote server at another OAuth client is a different server."""
        assert server_identity(_http({}, client_id="a")) != server_identity(_http({}, client_id="b"))

    def test_rotating_a_stored_secret_asks_nothing(self) -> None:
        """A credential supplied through an input reference can change without a new prompt."""
        config = _stdio(env={"API_TOKEN": "${input:token}", "PATH": "C:\\tools"})
        assert config.stdio is not None
        first = launch_digest(config.stdio, {"API_TOKEN": "one", "PATH": "C:\\tools"}, config.sandbox)
        second = launch_digest(config.stdio, {"API_TOKEN": "two", "PATH": "C:\\tools"}, config.sandbox)
        assert first == second

    def test_env_file_path_counts_and_its_secrets_do_not(self) -> None:
        """A ``PATH`` from the environment file changes the digest; a credential-named entry changes nothing."""
        config = _stdio(env_file="C:\\srv\\.env")
        assert config.stdio is not None
        base = launch_digest(config.stdio, {"PATH": "C:\\tools", "GITHUB_TOKEN": "ghp_one"}, config.sandbox)
        rotated = launch_digest(config.stdio, {"PATH": "C:\\tools", "GITHUB_TOKEN": "ghp_two"}, config.sandbox)
        moved = launch_digest(config.stdio, {"PATH": "C:\\evil", "GITHUB_TOKEN": "ghp_one"}, config.sandbox)
        assert base == rotated
        assert base != moved

    def test_launch_description_states_the_sandbox(self) -> None:
        """The operator reads whether the server is confined and what that leaves open."""
        sandboxed = _stdio(sandbox=replace(_SANDBOXED, allowed_domains=("api.example.com",)))
        assert sandboxed.stdio is not None
        confined = describe_launch(sandboxed.stdio, {}, sandboxed.sandbox)
        assert "Sandbox: ON" in confined
        assert "C:\\work" in confined
        assert "allowedDomains (api.example.com) is recorded only and is not enforced" in confined

        plain = _stdio()
        assert plain.stdio is not None
        assert "Sandbox: OFF" in describe_launch(plain.stdio, {}, plain.sandbox)

    def test_consent_dialog_shows_the_sandbox_state(self, qtbot: QtBot) -> None:
        """The consent dialog carries a label saying whether the server is sandboxed.

        Args:
            qtbot: The Qt test driver.
        """
        dialog = McpServerConsentDialog.for_config(_stdio(sandbox=_SANDBOXED), {})
        qtbot.addWidget(dialog)
        label = dialog.findChild(QLabel, "mcp_consent_sandbox")
        assert label is not None
        assert label.text().startswith("Sandbox: ON.")
        assert "Network access is not restricted" in label.text()

        unconfined = McpServerConsentDialog.for_config(_stdio(), {})
        qtbot.addWidget(unconfined)
        plain = unconfined.findChild(QLabel, "mcp_consent_sandbox")
        assert plain is not None
        assert plain.text().startswith("Sandbox: OFF.")


def _manager(tmp_path: Path, config: McpServerConfig, approvals: ApprovalStore) -> tuple[McpConnectionManager, McpConfigStore]:
    """Build a manager whose gate discards approvals when an identity changes.

    Args:
        tmp_path: Per-test directory.
        config: The one configured server.
        approvals: The approval store to discard from.

    Returns:
        tuple[McpConnectionManager, McpConfigStore]: The manager and its configuration store.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=(config,)))
    gate = McpConsentGate(
        TrustStore(tmp_path / "trust.json"),
        _RecordingPrompt(),
        on_identity_change=lambda server_id: approvals.invalidate_namespace(f"mcp-{server_id}"),
    )
    resolver = McpSecretResolver(CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))
    return McpConnectionManager(store, resolver, gate), store


class TestApprovalsFollowIdentity:
    """Item 4: an ``always`` approval applies only to the server it was given about."""

    def test_remote_server_repointed_loses_its_approvals(self, tmp_path: Path) -> None:
        """An HTTP server whose headers change no longer matches, and its persisted approvals are gone.

        Args:
            tmp_path: Per-test directory.
        """
        approvals = ApprovalStore(tmp_path / "approvals.json")
        with running_server(_SERVER_SCRIPT, "--mode", "well_behaved", "--transport", "http") as port:
            before = _http({"X-Tenant": "alpha"}, port=port)
            manager, store = _manager(tmp_path, before, approvals)
            source = McpToolSource(manager, ToolRegistry(tools_dir=tmp_path / "tools"))

            async def _run() -> tuple[str | None, str | None]:
                """Approve a tool, repoint the server, and read both approval keys.

                Returns:
                    tuple[str | None, str | None]: The key before and after.
                """
                await asyncio.wait_for(manager.start_server("remote"), timeout=_CONNECT_TIMEOUT_S)
                try:
                    first = source.approval_key_for("mcp-remote.echo")
                    assert first is not None
                    approvals.remember("mcp-remote", "mcp-remote.echo", first, approved=True, scope=ApprovalScope.ALWAYS)
                    assert approvals.decision("mcp-remote", "mcp-remote.echo", first) is True
                    store.save(McpConfigDocument(servers=(_http({"X-Tenant": "beta"}, port=port),)))
                    await asyncio.wait_for(manager.restart_server("remote"), timeout=_CONNECT_TIMEOUT_S)
                    return first, source.approval_key_for("mcp-remote.echo")
                finally:
                    await manager.stop()

            first, second = asyncio.run(_run())

        assert first is not None
        assert second is not None
        assert first != second
        assert approvals.decision("mcp-remote", "mcp-remote.echo", second) is None
        assert approvals.decision("mcp-remote", "mcp-remote.echo", first) is None
        assert approvals.entries() == []

    def test_same_identity_keeps_its_approvals(self, tmp_path: Path) -> None:
        """Restarting an unchanged server keeps what the operator approved.

        Args:
            tmp_path: Per-test directory.
        """
        approvals = ApprovalStore(tmp_path / "approvals.json")
        with running_server(_SERVER_SCRIPT, "--mode", "well_behaved", "--transport", "http") as port:
            manager, _ = _manager(tmp_path, _http({"X-Tenant": "alpha"}, port=port), approvals)
            source = McpToolSource(manager, ToolRegistry(tools_dir=tmp_path / "tools"))

            async def _run() -> tuple[str | None, str | None]:
                """Approve a tool, restart the server, and read both approval keys.

                Returns:
                    tuple[str | None, str | None]: The key before and after.
                """
                await asyncio.wait_for(manager.start_server("remote"), timeout=_CONNECT_TIMEOUT_S)
                try:
                    first = source.approval_key_for("mcp-remote.echo")
                    assert first is not None
                    approvals.remember("mcp-remote", "mcp-remote.echo", first, approved=True, scope=ApprovalScope.ALWAYS)
                    await asyncio.wait_for(manager.restart_server("remote"), timeout=_CONNECT_TIMEOUT_S)
                    return first, source.approval_key_for("mcp-remote.echo")
                finally:
                    await manager.stop()

            first, second = asyncio.run(_run())

        assert first == second
        assert second is not None
        assert approvals.decision("mcp-remote", "mcp-remote.echo", second) is True


class TestConcurrentWritesLoseNothing:
    """Item 5: the trust and approval files survive concurrent writers."""

    def test_threads_writing_through_two_stores_keep_every_record(self, tmp_path: Path) -> None:
        """Writers on many threads, through two store instances on one file, lose nothing.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "trust.json"
        stores = (TrustStore(path), TrustStore(path))
        start = threading.Barrier(_WRITERS)
        failures: list[BaseException] = []

        def _write(writer: int) -> None:
            """Record this writer's servers.

            Args:
                writer: The writer's index.
            """
            store = stores[writer % 2]
            start.wait()
            try:
                for record in range(_RECORDS_PER_WRITER):
                    store.set_state(f"s{writer}-{record}", TrustState.TRUSTED, identity=f"id{writer}")
            except McpConsentStoreError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=_write, args=(writer,)) for writer in range(_WRITERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert failures == []
        recorded = json.loads(path.read_text(encoding="utf-8"))
        assert len(recorded) == _WRITERS * _RECORDS_PER_WRITER
        assert not list(tmp_path.glob("trust.json.*.tmp"))

    def test_processes_writing_at_once_keep_every_record(self, tmp_path: Path) -> None:
        """Separate processes writing the same approvals file lose nothing.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "approvals.json"
        release = time.time() + 4.0
        code = f"""
            import json, time
            from pathlib import Path
            from intellicrack.mcp.consent import ApprovalScope, ApprovalStore
            store = ApprovalStore(Path({str(path)!r}))
            while time.time() < {release!r}:
                time.sleep(0.005)
            import os
            for index in range({_RECORDS_PER_PROCESS}):
                store.remember("mcp-x", f"mcp-x.t{{os.getpid()}}_{{index}}", "g@i", approved=True, scope=ApprovalScope.ALWAYS)
            print(json.dumps({{"pid": os.getpid()}}))
        """
        outcomes: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def _child() -> None:
            """Run one writer process."""
            try:
                outcomes.append(run_child_json(code, timeout_s=90.0))
            except AssertionError as exc:
                errors.append(exc)

        workers = [threading.Thread(target=_child) for _ in range(_PROCESSES)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=120)

        assert errors == []
        assert len(outcomes) == _PROCESSES
        recorded = json.loads(path.read_text(encoding="utf-8"))
        assert len(recorded) == _PROCESSES * _RECORDS_PER_PROCESS

    def test_a_corrupt_file_is_never_overwritten(self, tmp_path: Path) -> None:
        """A file that cannot be parsed is left exactly as it is, and the change is refused loudly.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "trust.json"
        damaged = '{"precious": {"state": "trusted"'
        path.write_text(damaged, encoding="utf-8")
        store = TrustStore(path)

        with pytest.raises(McpConsentStoreError, match="left as it was"):
            store.set_state("other", TrustState.DENIED)
        with pytest.raises(McpConsentStoreError):
            ApprovalStore(path).remember("mcp-x", "mcp-x.y", "g@i", approved=True, scope=ApprovalScope.ALWAYS)

        assert path.read_text(encoding="utf-8") == damaged
        assert store.state("precious") is TrustState.UNTRUSTED

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="Windows refuses to rename over a file another handle holds open without delete sharing (WinError 5)",
    )
    def test_rename_waits_out_a_reader_holding_the_file_open(self, tmp_path: Path) -> None:
        """A handle held open elsewhere delays the write instead of dropping it.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "trust.json"
        store = TrustStore(path)
        store.set_state("first", TrustState.TRUSTED)
        opened = threading.Event()

        def _hold() -> None:
            """Hold the file open for a moment, the way a scanner does."""
            with path.open(encoding="utf-8"):
                opened.set()
                time.sleep(0.3)

        holder = threading.Thread(target=_hold)
        holder.start()
        assert opened.wait(timeout=5)
        store.set_state("second", TrustState.TRUSTED)
        holder.join(timeout=5)

        recorded = json.loads(path.read_text(encoding="utf-8"))
        assert set(recorded) == {"first", "second"}
