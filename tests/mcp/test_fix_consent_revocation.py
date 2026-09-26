# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for revoking and re-deciding launch consent, trust and approvals.

Every decision the operator makes about a server has to be one they can take
back, and none may outlive the thing it was made about: a single "no" is not
"never", a changed launch is not the launch that was trusted, and a new server
reusing an old id is not the old server. The gate and stores are exercised
with real files on disk and, where a launch is involved, a real server over a
real stdio pipe.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import (
    ApprovalScope,
    ApprovalStore,
    ConsentAnswer,
    DangerousPattern,
    McpConsentGate,
    TrustState,
    TrustStore,
    deny_all_launches,
)
from intellicrack.mcp.errors import McpConsentDeniedError
from intellicrack.mcp.secrets import McpSecretResolver


_SERVER_SCRIPT = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_interactive_server.py"


def _stdio(server_id: str = "srv", *extra: str) -> McpServerConfig:
    """Build a stdio configuration for the interactive fixture server.

    Args:
        server_id: Identifier for the server.
        *extra: Extra arguments, which change the launch.

    Returns:
        McpServerConfig: An enabled configuration.
    """
    spec = StdioServerSpec(command=sys.executable, args=(str(_SERVER_SCRIPT), *extra))
    return McpServerConfig(server_id=server_id, kind=McpTransportKind.STDIO, stdio=spec, enabled=True, request_timeout_s=30.0)


class _ScriptedPrompt:
    """Answers launch prompts from a script and counts how often it was asked."""

    def __init__(self, answers: list[bool | ConsentAnswer]) -> None:
        """Initialize the prompt.

        Args:
            answers: The answers to give, in order.
        """
        self._answers = answers
        self.asked = 0

    def __call__(self, config: McpServerConfig, description: str, findings: list[DangerousPattern]) -> bool | ConsentAnswer:
        """Give the next scripted answer.

        Args:
            config: The server being launched.
            description: The rendered launch description.
            findings: Flagged patterns.

        Returns:
            bool | ConsentAnswer: The scripted answer.
        """
        del config, description, findings
        self.asked += 1
        return self._answers.pop(0)


def _consent(gate: McpConsentGate, config: McpServerConfig, env: dict[str, str] | None = None) -> None:
    """Ask the gate for consent to launch one server.

    Args:
        gate: The gate to ask.
        config: The server to launch.
        env: The resolved environment the launch would receive.
    """
    asyncio.run(gate.ensure_launch_consent(config, env or {}))


class TestRefusalIsNotForever:
    """A plain "no" refuses once; only an explicit block refuses for good."""

    def test_refusal_asks_again_next_time(self, tmp_path: Path) -> None:
        """After a refusal the server is not marked denied, and the next start asks again.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        prompt = _ScriptedPrompt([False, True])
        gate = McpConsentGate(trust, prompt)
        config = _stdio()

        with pytest.raises(McpConsentDeniedError):
            _consent(gate, config)
        assert trust.state("srv") is not TrustState.DENIED, "a single refusal marked the server denied forever"

        _consent(gate, config)
        assert prompt.asked == 2, "the second start was not asked about"

    def test_block_denies_until_reset(self, tmp_path: Path) -> None:
        """A never-start answer denies every later start without asking, until reset.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        prompt = _ScriptedPrompt([ConsentAnswer(approved=False, blocked=True), True])
        gate = McpConsentGate(trust, prompt)
        config = _stdio()

        with pytest.raises(McpConsentDeniedError):
            _consent(gate, config)
        assert trust.state("srv") is TrustState.DENIED
        with pytest.raises(McpConsentDeniedError, match="Trust and approvals tab of MCP Settings"):
            _consent(gate, config)
        assert prompt.asked == 1, "a blocked server was asked about again"

        trust.reset("srv")
        _consent(gate, config)
        assert prompt.asked == 2

    def test_headless_refusal_leaves_no_denial(self, tmp_path: Path) -> None:
        """With nobody to ask, a launch is refused without recording a denial.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        gate = McpConsentGate(trust, deny_all_launches)

        with pytest.raises(McpConsentDeniedError):
            _consent(gate, _stdio())
        assert trust.state("srv") is TrustState.UNTRUSTED


class TestTrustFollowsTheLaunch:
    """Trust granted about one launch does not carry over to another."""

    def test_changed_launch_approved_without_trust_drops_trust(self, tmp_path: Path) -> None:
        """Approving a changed launch without ticking trust withdraws the old trust.

        The launch changes only in the environment it receives, which is part
        of what the operator approves but not of the server's identity, so
        this is decided by the approval alone.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        prompt = _ScriptedPrompt([ConsentAnswer(approved=True, trusted=True), ConsentAnswer(approved=True)])
        gate = McpConsentGate(trust, prompt)
        config = _stdio()
        gate.set_config_lookup({"srv": config}.get)

        _consent(gate, config)
        assert gate.is_trusted("srv")
        _consent(gate, config, {"EXTRA_SECRET": "value"})
        assert prompt.asked == 2, "the changed launch was not asked about"
        assert not gate.is_trusted("srv"), "trust granted about the old launch survived approving a new one"

    def test_new_server_under_an_old_id_is_not_trusted(self, tmp_path: Path) -> None:
        """A different endpoint reusing a trusted server's id is not trusted.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        gate = McpConsentGate(trust, _ScriptedPrompt([ConsentAnswer(approved=True, trusted=True)]))
        _consent(gate, _stdio("files"))
        assert gate.is_trusted("files")

        replacement = McpServerConfig(
            server_id="files",
            kind=McpTransportKind.HTTP,
            http=HttpServerSpec(url="https://example.invalid/mcp"),
            enabled=True,
        )
        gate.set_config_lookup({"files": replacement}.get)
        assert not gate.is_trusted("files"), "a new server under a trusted server's id inherited its trust"

    def test_denial_of_another_server_does_not_block_a_new_one(self, tmp_path: Path) -> None:
        """A new command under a denied id is asked about instead of being refused.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        prompt = _ScriptedPrompt([ConsentAnswer(approved=False, blocked=True), True])
        gate = McpConsentGate(trust, prompt)
        with pytest.raises(McpConsentDeniedError):
            _consent(gate, _stdio())
        _consent(gate, _stdio("srv", "--another-program"))
        assert prompt.asked == 2

    def test_approved_launch_starts_a_real_server_after_a_refusal(self, tmp_path: Path) -> None:
        """A refused server really starts the next time the operator agrees.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), _ScriptedPrompt([False, True]))
        config = _stdio()

        async def body() -> tuple[bool, bool]:
            """Refuse, then approve, a real launch.

            Returns:
                tuple[bool, bool]: Whether the first and second attempts
                became ready.
            """
            outcomes: list[bool] = []
            for _attempt in range(2):
                connection = McpConnection(config, McpSecretResolver(CredentialStore()), consent=gate)
                try:
                    await connection.connect()
                except McpConsentDeniedError:
                    outcomes.append(False)
                    continue
                outcomes.append(connection.is_ready)
                await connection.disconnect()
            return outcomes[0], outcomes[1]

        first, second = asyncio.run(body())
        assert not first
        assert second, "the server stayed refused after the operator agreed"


class TestApprovalStore:
    """Remembered tool-call answers can be listed and revoked, and never outlive their tool."""

    def test_always_needs_a_generation(self, tmp_path: Path) -> None:
        """An 'always' answer without a generation is refused rather than stored forever.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = ApprovalStore(tmp_path / "approvals.json")
        with pytest.raises(ValueError, match="generation"):
            store.remember("ghidra", "patch_bytes", "", approved=True, scope=ApprovalScope.ALWAYS)
        assert not (tmp_path / "approvals.json").exists()

    def test_unversioned_persisted_answer_is_ignored_and_listed(self, tmp_path: Path) -> None:
        """A legacy answer stored without a generation is not honoured, but is listed for revocation.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "approvals.json"
        _ = path.write_text('{"ghidra|patch_bytes|": true}\n', encoding="utf-8")
        store = ApprovalStore(path)
        assert store.decision("ghidra", "patch_bytes", "") is None
        listed = store.entries()
        assert [(entry.namespace, entry.function_name, entry.generation) for entry in listed] == [("ghidra", "patch_bytes", "")]
        assert store.revoke("ghidra", "patch_bytes", "")
        assert store.entries() == []

    def test_revoke_all_forgets_both_scopes(self, tmp_path: Path) -> None:
        """Revoking everything clears session and persisted answers alike.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = ApprovalStore(tmp_path / "approvals.json")
        store.remember("mcp-files", "mcp-files.read", "g1", approved=True, scope=ApprovalScope.ALWAYS)
        store.remember("mcp-files", "mcp-files.write", "g1", approved=False, scope=ApprovalScope.SESSION)
        assert {(entry.function_name, entry.scope) for entry in store.entries()} == {
            ("mcp-files.read", ApprovalScope.ALWAYS),
            ("mcp-files.write", ApprovalScope.SESSION),
        }
        assert store.revoke_all() == 2
        assert store.entries() == []
        assert store.decision("mcp-files", "mcp-files.read", "g1") is None
