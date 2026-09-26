# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Operator consent for Model Context Protocol servers and their tools.

Three decisions live here, and they are deliberately separate.

Launch consent gates spawning a local server. The operator is shown the exact command with every argument untruncated, the names of the
environment entries it will receive, its working directory, and the warning that it runs with their own privileges. Nothing is spawned
before they agree. The decision is bound to a digest of that exact launch, so changing an argument asks again.

Trust decides whether a server's own claims about its tools may be believed. An untrusted server's ``readOnlyHint`` buys it nothing: every
call it offers is classified destructive and confirmed.

Approval records per-tool answers under ``once``, ``session`` or ``always``, keyed by the server's tool-listing generation. A server that
changes what its tools are produces a new generation, which invalidates what the operator approved of the old ones.
"""

from __future__ import annotations

import enum
import hashlib
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from intellicrack.core.config import get_config_file
from intellicrack.core.json_payload import JsonObject, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.mcp.catalog import canonical_json
from intellicrack.mcp.errors import McpConsentDeniedError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Mapping, Sequence

    from intellicrack.mcp.config import McpServerConfig, StdioServerSpec


_logger = get_logger(__name__)


TRUST_FILENAME: Final[str] = "mcp_trust.json"
"""File holding per-server trust state and approved launch digests."""

APPROVALS_FILENAME: Final[str] = "mcp_approvals.json"
"""File holding per-tool approvals the operator chose to keep."""

_LAUNCH_DIGEST_BYTES: Final[int] = 16

_HOME_MARKERS: Final[tuple[str, ...]] = ("~", "%userprofile%", "$home", "$env:userprofile")
_SYSTEM_MARKERS: Final[tuple[str, ...]] = (
    "c:\\windows",
    "%systemroot%",
    "%windir%",
    "\\system32",
    "/etc/",
    "/usr/bin",
    "/usr/sbin",
    "/sbin/",
    "/boot/",
)
_CREDENTIAL_MARKERS: Final[tuple[str, ...]] = (".ssh", ".aws", ".gnupg", ".kube", "id_rsa", "credentials.json")

_SHELL_FETCH_TOKENS: Final[frozenset[str]] = frozenset({"curl", "wget", "iwr", "invoke-webrequest", "certutil", "bitsadmin"})
_SHELL_EXECUTE_TOKENS: Final[frozenset[str]] = frozenset({"sh", "bash", "zsh", "cmd", "powershell", "pwsh", "iex", "invoke-expression"})


class TrustState(enum.Enum):
    """How far a server's own claims may be believed.

    Attributes:
        UNTRUSTED: The default. Tool annotations are ignored and every call
            is treated as destructive.
        TRUSTED: The operator vouched for this server. Its
            ``readOnlyHint`` is honoured during classification.
        DENIED: The operator refused this server. It is never launched or
            connected.
    """

    UNTRUSTED = "untrusted"
    TRUSTED = "trusted"
    DENIED = "denied"


class ApprovalScope(enum.Enum):
    """How long an operator's answer to a tool confirmation lasts.

    Attributes:
        ONCE: Applies to this call only; nothing is recorded.
        SESSION: Applies until the application exits.
        ALWAYS: Persisted, and survives a restart until the server's tool
            listing changes.
    """

    ONCE = "once"
    SESSION = "session"
    ALWAYS = "always"


@dataclass(frozen=True, slots=True)
class DangerousPattern:
    """One reason a proposed launch deserves a second look.

    Attributes:
        token: The fragment of the command line that triggered the finding.
        reason: What makes it worth the operator's attention.
    """

    token: str
    reason: str


def _scan_token(token: str, lowered: str) -> DangerousPattern | None:
    """Classify one command-line token against the location-based findings.

    Args:
        token: The token as written, used in the finding.
        lowered: The token lower-cased, used for matching.

    Returns:
        DangerousPattern | None: The finding, or ``None`` when the token is
        unremarkable.
    """
    if any(marker in lowered for marker in _CREDENTIAL_MARKERS):
        return DangerousPattern(token=token, reason="references a credential or key directory")
    if any(marker in lowered for marker in _SYSTEM_MARKERS):
        return DangerousPattern(token=token, reason="reaches into a system directory")
    if lowered.startswith(_HOME_MARKERS) or "%userprofile%" in lowered:
        return DangerousPattern(token=token, reason="reaches into your home directory")
    return None


def _scan_flags(token: str, lowered: str) -> DangerousPattern | None:
    """Classify one command-line token against the flag-based findings.

    Args:
        token: The token as written, used in the finding.
        lowered: The token lower-cased, used for matching.

    Returns:
        DangerousPattern | None: The finding, or ``None`` when the token is
        unremarkable.
    """
    if lowered in {"-enc", "-e", "-encodedcommand", "--encodedcommand"}:
        return DangerousPattern(token=token, reason="runs a base64-encoded command you cannot read")
    if lowered in {"-executionpolicy", "--executionpolicy", "bypass"}:
        return DangerousPattern(token=token, reason="disables PowerShell script-execution policy")
    if lowered in {"-nop", "-noprofile", "-w", "-windowstyle"}:
        return DangerousPattern(token=token, reason="suppresses the usual PowerShell startup and window")
    if lowered in {"-c", "/c", "/k", "-command", "--command", "-eval", "eval"}:
        return DangerousPattern(token=token, reason="passes a command string to an interpreter")
    if lowered in {"-rf", "-fr", "-rf/", "--recursive"}:
        return DangerousPattern(token=token, reason="recursive file operation")
    return None


def scan_command_for_dangerous_patterns(command: str, args: Sequence[str]) -> list[DangerousPattern]:
    """Find everything about a proposed launch worth flagging to the operator.

    The scan is advisory: it never blocks a launch on its own, it raises the
    operator's attention before they answer. Findings cover privilege
    escalation, recursive deletion, fetch-and-execute pipelines, opaque
    encoded commands, and paths that reach into the home directory,
    credential stores, or system locations.

    Args:
        command: The configured launch command.
        args: The configured arguments.

    Returns:
        list[DangerousPattern]: Findings in command-line order, without
        duplicates.
    """
    findings: dict[tuple[str, str], DangerousPattern] = {}

    def _record(pattern: DangerousPattern | None) -> None:
        """Keep one finding, discarding an exact repeat.

        Args:
            pattern: The finding to keep, or ``None``.
        """
        if pattern is not None:
            findings.setdefault((pattern.token, pattern.reason), pattern)

    tokens = [command, *args]
    lowered_tokens = [token.lower() for token in tokens]

    for token, lowered in zip(tokens, lowered_tokens, strict=True):
        base = Path(lowered).name
        if base in {"sudo", "runas", "doas", "gsudo"}:
            _record(DangerousPattern(token=token, reason="requests elevated privileges"))
        if base in {"rm", "del", "rmdir", "remove-item"}:
            _record(DangerousPattern(token=token, reason="deletes files"))
        _record(_scan_flags(token, lowered))
        _record(_scan_token(token, lowered))

    bases = {Path(lowered).name.removesuffix(".exe") for lowered in lowered_tokens}
    if bases & _SHELL_FETCH_TOKENS and bases & _SHELL_EXECUTE_TOKENS:
        _record(
            DangerousPattern(
                token=" ".join(tokens),
                reason="downloads content and feeds it straight to an interpreter",
            ),
        )

    return list(findings.values())


def describe_launch(spec: StdioServerSpec, env: Mapping[str, str]) -> str:
    """Render exactly what will be run, for the operator to read before agreeing.

    Every argument appears in full: nothing is truncated, elided or
    reflowed, because an argument the operator cannot see is an argument
    they cannot refuse. Environment entries appear by name only -- their
    values are resolved credentials and must never be displayed.

    Args:
        spec: The configured launch description.
        env: The fully resolved environment the child will receive.

    Returns:
        str: A plain-text description suitable for a monospace, read-only view.
    """
    lines: list[str] = [
        "Intellicrack is about to start a local program on your computer.",
        "It will run with your own user account and your own privileges:",
        "anything you can read, write or delete, it can too.",
        "",
        "Command:",
        f"  {spec.command}",
    ]

    if spec.args:
        lines.extend(("", f"Arguments ({len(spec.args)}):"))
        lines.extend(f"  [{index}] {argument}" for index, argument in enumerate(spec.args))
    else:
        lines.extend(["", "Arguments:", "  (none)"])

    lines.extend(
        [
            "",
            "Working directory:",
            f"  {spec.cwd or '(inherited from Intellicrack)'}",
            "",
        ],
    )
    if env:
        lines.append(f"Environment entries passed to it ({len(env)}), values hidden:")
        lines.extend(f"  {name}" for name in sorted(env))
    else:
        lines.extend(("Environment entries passed to it:", "  (none beyond the inherited environment)"))

    if spec.env_file is not None:
        lines.extend(["", "Environment file:", f"  {spec.env_file}"])

    findings = scan_command_for_dangerous_patterns(spec.command, spec.args)
    lines.append("")
    if findings:
        lines.append(f"Flagged for your attention ({len(findings)}):")
        lines.extend(f"  {finding.token} -- {finding.reason}" for finding in findings)
    else:
        lines.extend((
            "Nothing in this command matched Intellicrack's list of risky patterns.",
            "That is not a guarantee that it is safe; read the command above.",
        ))

    return "\n".join(lines)


def launch_digest(spec: StdioServerSpec, env: Mapping[str, str]) -> str:
    """Digest the exact launch an operator is being asked to approve.

    Covers the command, every argument in order, the working directory and
    the environment entry names -- but not their values, so rotating a
    credential does not force a fresh consent prompt while changing what
    runs does.

    Args:
        spec: The configured launch description.
        env: The resolved environment the child will receive.

    Returns:
        str: A hexadecimal digest, stable across processes.
    """
    material = canonical_json({
        "command": spec.command,
        "args": list(spec.args),
        "cwd": spec.cwd,
        "envNames": sorted(env),
        "envFile": spec.env_file,
    })
    return hashlib.blake2b(material.encode("utf-8"), digest_size=_LAUNCH_DIGEST_BYTES).hexdigest()


def server_identity(config: McpServerConfig) -> str:
    """Digest what makes a configured server the server the operator judged.

    Trust, refusals and approved launches are filed under a server id, but an
    id is only a name: removing a server and adding a different one under the
    same id must not hand the newcomer the old one's standing. The identity
    covers the transport and where it leads -- the launch command, its
    arguments, working directory and environment file for a local server, the
    endpoint and its query for a remote one -- so a record made about one
    program or endpoint is never applied to another.

    Args:
        config: The configured server.

    Returns:
        str: A hexadecimal digest, stable across processes.
    """
    material: dict[str, object] = {"kind": config.kind.value}
    if config.stdio is not None:
        material |= {
            "command": config.stdio.command,
            "args": list(config.stdio.args),
            "cwd": config.stdio.cwd,
            "envFile": config.stdio.env_file,
        }
    if config.http is not None:
        material |= {"url": config.http.url, "query": dict(config.http.query)}
    return hashlib.blake2b(canonical_json(material).encode("utf-8"), digest_size=_LAUNCH_DIGEST_BYTES).hexdigest()


def _read_json_object(path: Path) -> JsonObject:
    """Read a JSON object from disk, treating any fault as an empty document.

    A consent record that cannot be read must not be guessed at. Returning
    an empty document makes every server untrusted and every approval
    absent, which is the safe direction to fail in.

    Args:
        path: File to read.

    Returns:
        JsonObject: The decoded object, or an empty mapping.
    """
    empty: JsonObject = {}
    if not path.exists():
        return empty
    try:
        decoded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _logger.warning("mcp_consent_store_unreadable", path=str(path), error=str(exc))
        return empty
    if not is_json_object(decoded):
        _logger.warning("mcp_consent_store_malformed", path=str(path))
        return empty
    return decoded


def _write_json_object(path: Path, data: Mapping[str, Any]) -> None:
    """Write a JSON object to disk atomically.

    Args:
        path: File to write.
        data: The object to store.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.tmp")
        _ = temporary.write_text(f"{json.dumps(data, indent=2, sort_keys=True)}\n", encoding="utf-8")
        _ = temporary.replace(path)
    except OSError as exc:
        _logger.warning("mcp_consent_store_unwritable", path=str(path), error=str(exc))


class TrustStore:
    """Per-server trust state, approved launches, and the last seen generation.

    Persisted so an operator's answer survives a restart, and reloaded on every read so an external edit to the file takes effect without
    restarting the application.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the store.

        Args:
            path: File to persist to. Defaults to
                ``<config_dir>/mcp_trust.json``.
        """
        self._path = path if path is not None else get_config_file(TRUST_FILENAME)

    @property
    def path(self) -> Path:
        """Location of the file this store persists to.

        Returns:
            Path: The trust file path.
        """
        return self._path

    def _entry(self, server_id: str) -> JsonObject:
        """Read one server's record.

        Args:
            server_id: The server to read.

        Returns:
            JsonObject: The record, or an empty mapping.
        """
        entry = _read_json_object(self._path).get(server_id)
        return entry if is_json_object(entry) else {}

    def _update(self, server_id: str, changes: Mapping[str, Any]) -> None:
        """Merge changes into one server's record and persist.

        Args:
            server_id: The server to update.
            changes: Fields to set.
        """
        data = _read_json_object(self._path)
        entry = data.get(server_id)
        merged: dict[str, Any] = dict(entry) if is_json_object(entry) else {}
        merged |= changes
        data[server_id] = merged
        _write_json_object(self._path, data)

    def state(self, server_id: str) -> TrustState:
        """Read a server's trust state.

        Args:
            server_id: The server to read.

        Returns:
            TrustState: The recorded state, defaulting to
            :attr:`TrustState.UNTRUSTED`.
        """
        raw = self._entry(server_id).get("state")
        if not isinstance(raw, str):
            return TrustState.UNTRUSTED
        try:
            return TrustState(raw)
        except ValueError:
            _logger.warning("mcp_trust_state_unknown", server_id=server_id, state=raw)
            return TrustState.UNTRUSTED

    def set_state(self, server_id: str, state: TrustState, *, identity: str | None = None) -> None:
        """Record a server's trust state.

        Args:
            server_id: The server to update.
            state: The state to record.
            identity: The :func:`server_identity` of the server the operator
                judged, binding the record to it. ``None`` leaves the bound
                identity unchanged.
        """
        changes: dict[str, str] = {"state": state.value}
        if identity is not None:
            changes["identity"] = identity
        self._update(server_id, changes)
        _logger.info("mcp_trust_state_set", server_id=server_id, state=state.value)

    def identity(self, server_id: str) -> str | None:
        """Read the identity a server's record is bound to.

        Args:
            server_id: The server to read.

        Returns:
            str | None: The :func:`server_identity` recorded with the
            operator's last decision, or ``None`` for a record that predates
            identity binding or does not exist.
        """
        raw = self._entry(server_id).get("identity")
        return raw if isinstance(raw, str) else None

    def belongs_to(self, config: McpServerConfig) -> bool:
        """Report whether a server's record was made about this configuration.

        Args:
            config: The server as currently configured.

        Returns:
            bool: ``False`` only when the record is bound to a different
            identity, meaning the id now names another program or endpoint.
        """
        recorded = self.identity(config.server_id)
        return recorded is None or recorded == server_identity(config)

    def state_for(self, config: McpServerConfig) -> TrustState:
        """Read a server's trust state, honouring it only for the server it was given to.

        Args:
            config: The server as currently configured.

        Returns:
            TrustState: The recorded state when the record belongs to this
            configuration, and :attr:`TrustState.UNTRUSTED` when it was made
            about a different program or endpoint under the same id.
        """
        if not self.belongs_to(config):
            return TrustState.UNTRUSTED
        return self.state(config.server_id)

    def generation(self, server_id: str) -> str | None:
        """Read the tool-listing generation last seen for a server.

        Args:
            server_id: The server to read.

        Returns:
            str | None: The recorded generation, or ``None``.
        """
        raw = self._entry(server_id).get("generation")
        return raw if isinstance(raw, str) else None

    def set_generation(self, server_id: str, generation: str) -> None:
        """Record the tool-listing generation currently in effect.

        Args:
            server_id: The server to update.
            generation: The generation digest to record.
        """
        self._update(server_id, {"generation": generation})

    def launch_digest(self, server_id: str) -> str | None:
        """Read the launch an operator last approved for a server.

        Args:
            server_id: The server to read.

        Returns:
            str | None: The approved launch digest, or ``None`` when the
            operator has never approved a launch for it.
        """
        raw = self._entry(server_id).get("launchDigest")
        return raw if isinstance(raw, str) else None

    def set_launch_digest(self, server_id: str, digest: str, *, identity: str | None = None) -> None:
        """Record the launch an operator has just approved.

        Args:
            server_id: The server to update.
            digest: The launch digest to record.
            identity: The :func:`server_identity` of the server approved,
                or ``None`` to leave the bound identity unchanged.
        """
        changes: dict[str, str] = {"launchDigest": digest}
        if identity is not None:
            changes["identity"] = identity
        self._update(server_id, changes)

    def reset(self, server_id: str) -> None:
        """Forget everything recorded for one server.

        Args:
            server_id: The server to forget.
        """
        data = _read_json_object(self._path)
        if data.pop(server_id, None) is not None:
            _write_json_object(self._path, data)
            _logger.info("mcp_trust_reset", server_id=server_id)


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """One remembered answer to a tool confirmation.

    Attributes:
        namespace: The tool namespace, e.g. ``mcp-files``.
        function_name: The canonical dotted function name.
        generation: The tool-listing generation the answer was given about.
            Empty for an answer recorded without one, which no longer
            applies to anything.
        approved: ``True`` for an approval, ``False`` for a refusal.
        scope: How long the answer lasts.
    """

    namespace: str
    function_name: str
    generation: str
    approved: bool
    scope: ApprovalScope


def _split_approval_key(key: str) -> tuple[str, str, str] | None:
    """Split a stored approval key back into its three parts.

    Args:
        key: A key built by :meth:`ApprovalStore._key`.

    Returns:
        tuple[str, str, str] | None: The namespace, function name and
        generation, or ``None`` for a key that is not one of ours.
    """
    namespace, separator, remainder = key.partition("|")
    function_name, second, generation = remainder.rpartition("|")
    if not separator or not second or not namespace or not function_name:
        return None
    return namespace, function_name, generation


class ApprovalStore:
    """Per-tool approvals, keyed by namespace, function name and generation.

    ``session`` answers live in memory for the life of the process. ``always`` answers are persisted. Both are keyed by the generation of
    the server's tool listing, so an answer never carries over to a tool whose definition has changed underneath it.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the store.

        Args:
            path: File to persist ``always`` answers to. Defaults to
                ``<config_dir>/mcp_approvals.json``.
        """
        self._path = path if path is not None else get_config_file(APPROVALS_FILENAME)
        self._session: dict[str, bool] = {}

    @property
    def path(self) -> Path:
        """Location of the file this store persists to.

        Returns:
            Path: The approvals file path.
        """
        return self._path

    @staticmethod
    def _key(namespace: str, function_name: str, generation: str) -> str:
        """Build the storage key for one approval.

        Args:
            namespace: The server namespace, e.g. ``mcp-files``.
            function_name: The canonical dotted function name.
            generation: The server's tool-listing generation.

        Returns:
            str: The composite key.
        """
        return f"{namespace}|{function_name}|{generation}"

    def decision(self, namespace: str, function_name: str, generation: str) -> bool | None:
        """Look up a remembered answer.

        Args:
            namespace: The server namespace.
            function_name: The canonical dotted function name.
            generation: The server's current tool-listing generation.

        Returns:
            bool | None: ``True`` for a remembered approval, ``False`` for a
            remembered refusal, ``None`` when the operator must be asked.
        """
        key = self._key(namespace, function_name, generation)
        if key in self._session:
            return self._session[key]
        if not generation:
            return None
        stored = _read_json_object(self._path).get(key)
        return stored if isinstance(stored, bool) else None

    def remember(
        self,
        namespace: str,
        function_name: str,
        generation: str,
        *,
        approved: bool,
        scope: ApprovalScope,
    ) -> None:
        """Record an operator's answer for the requested duration.

        Args:
            namespace: The server namespace.
            function_name: The canonical dotted function name.
            generation: The server's current tool-listing generation.
            approved: The operator's answer.
            scope: How long the answer applies.

        Raises:
            ValueError: If an ``always`` answer is given without a
                generation. Such an answer could never be invalidated, so it
                would outlive any change to what the tool does.
        """
        if scope is ApprovalScope.ONCE:
            return
        key = self._key(namespace, function_name, generation)
        if scope is ApprovalScope.SESSION:
            self._session[key] = approved
            return
        if not generation:
            message = f"an 'always' answer for {namespace}.{function_name} needs a tool-listing generation"
            raise ValueError(message)
        data = _read_json_object(self._path)
        data[key] = approved
        _write_json_object(self._path, data)
        _logger.info(
            "mcp_approval_persisted",
            namespace=namespace,
            function_name=function_name,
            approved=approved,
        )

    def invalidate_namespace(self, namespace: str) -> None:
        """Drop every remembered answer belonging to one server.

        Called when a server's tool listing changes, so the operator is
        asked again about tools they had already answered for.

        Args:
            namespace: The server namespace to clear.
        """
        prefix = f"{namespace}|"
        for key in [key for key in self._session if key.startswith(prefix)]:
            del self._session[key]
        data = _read_json_object(self._path)
        removed = [key for key in data if key.startswith(prefix)]
        if removed:
            for key in removed:
                del data[key]
            _write_json_object(self._path, data)
        _logger.info("mcp_approvals_invalidated", namespace=namespace, removed=len(removed))

    def clear_session(self) -> None:
        """Drop every ``session`` answer, leaving persisted ones in place."""
        self._session.clear()

    def entries(self) -> list[ApprovalRecord]:
        """List every remembered answer, session-scoped and persisted.

        Returns:
            list[ApprovalRecord]: The answers, session ones first, each group
            sorted by key.
        """
        records: list[ApprovalRecord] = []
        for scope, source in (
            (ApprovalScope.SESSION, dict(self._session)),
            (ApprovalScope.ALWAYS, _read_json_object(self._path)),
        ):
            for key in sorted(source):
                value = source[key]
                parts = _split_approval_key(key)
                if parts is None or not isinstance(value, bool):
                    continue
                namespace, function_name, generation = parts
                records.append(ApprovalRecord(namespace, function_name, generation, approved=value, scope=scope))
        return records

    def revoke(self, namespace: str, function_name: str, generation: str) -> bool:
        """Forget one remembered answer, in every scope it was kept in.

        Args:
            namespace: The tool namespace.
            function_name: The canonical dotted function name.
            generation: The generation the answer was recorded under.

        Returns:
            bool: ``True`` when anything was removed.
        """
        key = self._key(namespace, function_name, generation)
        removed = self._session.pop(key, None) is not None
        data = _read_json_object(self._path)
        if data.pop(key, None) is not None:
            _write_json_object(self._path, data)
            removed = True
        if removed:
            _logger.info("mcp_approval_revoked", namespace=namespace, function_name=function_name)
        return removed

    def revoke_all(self) -> int:
        """Forget every remembered answer.

        Returns:
            int: How many answers were removed.
        """
        data = _read_json_object(self._path)
        count = len(self._session) + len(data)
        self._session.clear()
        if data:
            _write_json_object(self._path, {})
        _logger.info("mcp_approvals_revoked_all", removed=count)
        return count


@dataclass(frozen=True, slots=True)
class ConsentAnswer:
    """The operator's full answer to a launch-consent prompt.

    Attributes:
        approved: Whether this launch may go ahead.
        trusted: Whether the operator also vouched for the server's claims
            about its own tools. Meaningful only with ``approved``.
        blocked: Whether the operator asked never to be asked about this
            server again, refusing it until the refusal is reset in MCP
            Settings. A plain refusal leaves the next start free to ask.
    """

    approved: bool
    trusted: bool = False
    blocked: bool = False


LaunchPrompt = Callable[["McpServerConfig", str, list["DangerousPattern"]], "bool | ConsentAnswer | Awaitable[bool | ConsentAnswer]"]
"""Presents a proposed launch and returns the operator's answer.

Receives the server configuration, the rendered description from :func:`describe_launch`, and the findings from
:func:`scan_command_for_dangerous_patterns`. A plain ``bool`` approves or refuses this launch alone; a :class:`ConsentAnswer` also carries
the trust and never-ask-again choices.

The answer may be awaitable. A prompt that shows a window has to hand the question to the GUI thread and wait for it, and awaiting that wait
keeps the loop free to serve every other server in the meantime -- rather than blocking all of them behind one modal dialog.
"""


def _as_answer(*, answer: bool | ConsentAnswer) -> ConsentAnswer:
    """Normalise a prompt's answer into a :class:`ConsentAnswer`.

    Args:
        answer: What the prompt returned.

    Returns:
        ConsentAnswer: The answer, a bare ``bool`` meaning approval or refusal
        of this launch alone.
    """
    return answer if isinstance(answer, ConsentAnswer) else ConsentAnswer(approved=bool(answer))


class McpConsentGate:
    """Decides whether a local server may be launched, asking when it must.

    A gate is consulted before anything is spawned. It answers from a recorded decision when the launch is byte-identical to one already
    approved, and otherwise asks -- which, headless, means refusing, because no prompt is available to ask through.
    """

    def __init__(
        self,
        trust: TrustStore,
        prompt: LaunchPrompt,
        on_generation_change: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the gate.

        Args:
            trust: Store holding trust state and approved launches.
            prompt: Callable that presents the launch and returns the
                operator's answer.
            on_generation_change: Invoked with the server id and its new
                generation whenever a server's tool listing changes. This is
                where remembered per-tool approvals are discarded, so an
                answer about the old definitions is never replayed against
                the new ones.
        """
        self._trust = trust
        self._prompt = prompt
        self._on_generation_change = on_generation_change
        self._config_lookup: Callable[[str], McpServerConfig | None] | None = None

    @property
    def trust(self) -> TrustStore:
        """The trust store this gate reads and writes.

        Returns:
            TrustStore: The backing store.
        """
        return self._trust

    def set_prompt(self, prompt: LaunchPrompt) -> None:
        """Replace the callable that asks the operator.

        Args:
            prompt: The new prompt. :func:`deny_all_launches` is the one to
                install once nobody is left to ask, such as while the
                application shuts down.
        """
        self._prompt = prompt

    def set_config_lookup(self, lookup: Callable[[str], McpServerConfig | None] | None) -> None:
        """Install how the gate finds a server's current configuration.

        Trust is recorded against a server's identity as well as its id. With
        a lookup installed, :meth:`is_trusted` honours a record only while the
        id still names the program or endpoint it was given to.

        Args:
            lookup: Returns the configuration for a server id, or ``None``
                when no such server is configured. ``None`` removes the
                lookup, leaving trust keyed by id alone.
        """
        self._config_lookup = lookup

    async def ensure_launch_consent(self, config: McpServerConfig, env: Mapping[str, str]) -> None:
        """Obtain consent to launch a local server, or refuse.

        Args:
            config: The server about to be launched.
            env: The fully resolved environment the child would receive.

        Raises:
            McpConsentDeniedError: If the server is marked denied, if it has
                no launch description, or if the operator refuses.
        """
        if config.stdio is None:
            message = f"server '{config.server_id}' has no launch command to consent to"
            raise McpConsentDeniedError(message)

        if not self._trust.belongs_to(config):
            _logger.warning("mcp_trust_record_for_other_server", server_id=config.server_id)
            self._trust.reset(config.server_id)

        if self._trust.state(config.server_id) is TrustState.DENIED:
            message = (
                f"server '{config.server_id}' is marked as never to be started; "
                "reset it on the Trust and approvals tab of MCP Settings to be asked again"
            )
            raise McpConsentDeniedError(message)

        digest = launch_digest(config.stdio, env)
        if self._trust.launch_digest(config.server_id) == digest:
            _logger.debug("mcp_launch_consent_recorded", server_id=config.server_id)
            return

        description = describe_launch(config.stdio, env)
        findings = scan_command_for_dangerous_patterns(config.stdio.command, config.stdio.args)
        _logger.info(
            "mcp_launch_consent_requested",
            server_id=config.server_id,
            command=config.stdio.command,
            argument_count=len(config.stdio.args),
            finding_count=len(findings),
        )
        answer = self._prompt(config, description, findings)
        if inspect.isawaitable(answer):
            answer = await answer
        if not self.record_answer(config, env, _as_answer(answer=answer)):
            message = f"launching MCP server '{config.server_id}' was not approved"
            raise McpConsentDeniedError(message)

    def record_answer(self, config: McpServerConfig, env: Mapping[str, str], answer: ConsentAnswer) -> bool:
        """Apply the operator's answer about one proposed launch.

        An approval records the exact launch, so the same launch is not asked
        about again. Trust follows the answer: ticking the trust box grants
        it, and approving a launch that differs from the one approved before
        without ticking it withdraws trust given about the old launch. A
        plain refusal records nothing, so the next start asks again; only an
        explicit never-ask-again marks the server denied.

        Args:
            config: The server the answer is about.
            env: The resolved environment the answer was given about.
            answer: The operator's answer.

        Returns:
            bool: ``True`` when the launch was approved.

        Raises:
            McpConsentDeniedError: If the server has no launch description.
        """
        if config.stdio is None:
            message = f"server '{config.server_id}' has no launch command to consent to"
            raise McpConsentDeniedError(message)
        server_id = config.server_id
        identity = server_identity(config)
        if answer.blocked:
            self._trust.set_state(server_id, TrustState.DENIED, identity=identity)
            _logger.warning("mcp_launch_blocked", server_id=server_id)
            return False
        if not answer.approved:
            _logger.warning("mcp_launch_consent_refused", server_id=server_id)
            return False

        digest = launch_digest(config.stdio, env)
        previous = self._trust.launch_digest(server_id)
        if answer.trusted:
            self._trust.set_state(server_id, TrustState.TRUSTED, identity=identity)
        elif previous is not None and previous != digest and self._trust.state(server_id) is TrustState.TRUSTED:
            self._trust.set_state(server_id, TrustState.UNTRUSTED, identity=identity)
            _logger.warning("mcp_trust_withdrawn_for_changed_launch", server_id=server_id)
        elif self._trust.state(server_id) is TrustState.DENIED:
            self._trust.set_state(server_id, TrustState.UNTRUSTED, identity=identity)
        self._trust.set_launch_digest(server_id, digest, identity=identity)
        _logger.info("mcp_launch_consent_granted", server_id=server_id, trusted=answer.trusted)
        return True

    def note_generation(self, server_id: str, generation: str) -> bool:
        """Record a server's current tool listing and report whether it moved.

        Args:
            server_id: The server that just published a listing.
            generation: The listing's generation digest.

        Returns:
            bool: ``True`` when the generation differs from the one last
            recorded, which is the caller's cue to invalidate every approval
            for this server and ask again.
        """
        previous = self._trust.generation(server_id)
        self._trust.set_generation(server_id, generation)
        changed = previous is not None and previous != generation
        if changed:
            _logger.warning(
                "mcp_tool_generation_changed",
                server_id=server_id,
                previous=previous,
                current=generation,
            )
            if self._on_generation_change is not None:
                self._on_generation_change(server_id, generation)
        return changed

    def is_trusted(self, server_id: str) -> bool:
        """Report whether a server's own tool claims may be believed.

        Args:
            server_id: The server to check.

        Returns:
            bool: ``True`` only when the operator marked it trusted.
        """
        lookup = self._config_lookup
        config = lookup(server_id) if lookup is not None else None
        state = self._trust.state_for(config) if config is not None else self._trust.state(server_id)
        return state is TrustState.TRUSTED


def deny_all_launches(config: McpServerConfig, description: str, findings: list[DangerousPattern]) -> bool:
    """Refuse every launch that would need an operator to answer.

    This is the prompt a headless process runs with. A local server is never
    started without a human agreeing, so with nobody to ask, the answer is
    no.

    Args:
        config: The server that would be launched.
        description: The rendered launch description.
        findings: Patterns flagged in the command.

    Returns:
        bool: Always ``False``.
    """
    _logger.warning(
        "mcp_launch_consent_unavailable",
        server_id=config.server_id,
        description_length=len(description),
        finding_count=len(findings),
    )
    return False
