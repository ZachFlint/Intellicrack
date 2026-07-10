# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data end-to-end coverage for orchestrator and session orchestration.

These tests drive the orchestrator's core mission against REAL binaries and a
real tool bridge:

* ``process_user_input`` runs the full agent loop -- the scripted provider
  emits a real :class:`ToolCall`, the orchestrator dispatches it to a real
  bridge that parses a real System32 PE (or the committed ELF corpus binary)
  with ``lief``, and the real imports / sections flow back into the session and
  are persisted to SQLite.
* ``add_binary`` and ``start_session(binary_path=...)`` load real binaries and
  populate :class:`BinaryInfo` with real sha256 digests, section names, and
  imports parsed by ``lief``.
* ``Session.add_binary`` / ``Session.add_message`` and ``SessionManager.load``
  round-trip real session state through the on-disk store.

The only test double is the LLM network transport: no model endpoint is
reachable in the offline/Docker harness, so a scripted provider stands in for
the remote API. Every operation actually under test (the agent loop, tool
dispatch to the real bridge, real binary parsing, and session persistence) runs
for real against real data.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, override

import lief
import pytest

from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.core.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    extract_exports,
    extract_imports,
)
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    BinaryInfo,
    ConfirmationLevel,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderName,
    SectionInfo,
    ToolCall,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from intellicrack.core.types import BridgeAnalysisSummary, ThinkingConfig, ToolChoice

    _LiefParseFn = Callable[
        [str],
        lief.PE.Binary | lief.OAT.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary | None,
    ]


def _parse_real_binary(path: Path) -> BinaryInfo:
    """Parse a real binary with ``lief`` into a typed :class:`BinaryInfo`.

    Uses the public ``extract_imports`` / ``extract_exports`` helpers from the
    orchestrator module and reads section metadata directly off the parsed
    ``lief`` binary, so the test never touches private parsing internals while
    still proving the same real ``lief`` pipeline the orchestrator relies on.

    Args:
        path: Filesystem path to the binary to parse.

    Returns:
        BinaryInfo: Populated metadata with real sha256, sections, imports, and
            exports parsed from the file.

    Raises:
        ValueError: If ``lief`` cannot identify the binary format.
    """
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    parser = cast("_LiefParseFn", vars(lief)["parse"])
    binary = parser(str(path))
    if binary is None:
        error_message = f"lief could not parse binary: {path}"
        raise ValueError(error_message)

    file_type = "unknown"
    is_64bit = False
    entry_point = 0
    if isinstance(binary, lief.PE.Binary):
        file_type = "pe"
        machine_str = str(getattr(binary.header, "machine", ""))
        is_64bit = "AMD64" in machine_str
        opt = binary.optional_header
        entry_point = int(opt.addressof_entrypoint) + int(opt.imagebase)
    elif isinstance(binary, lief.ELF.Binary):
        file_type = "elf"
        is_64bit = "64" in str(getattr(binary.header, "identity_class", ""))
        entry_point = int(binary.entrypoint)
    elif isinstance(binary, lief.MachO.Binary):
        file_type = "macho"
        is_64bit = "64" in str(getattr(binary.header, "cpu_type", ""))
        entry_point = int(binary.entrypoint)

    sections = [
        SectionInfo(
            name=str(sec.name),
            virtual_address=int(sec.virtual_address),
            virtual_size=int(sec.size),
            raw_size=int(sec.size),
            characteristics=0,
            entropy=0.0,
        )
        for sec in binary.sections
    ]
    return BinaryInfo(
        path=path,
        name=path.name,
        size=len(raw),
        sha256=sha256,
        file_type=file_type,
        architecture="unknown",
        is_64bit=is_64bit,
        entry_point=entry_point,
        sections=sections,
        imports=extract_imports(binary),
        exports=extract_exports(binary),
    )


_MODEL_ID: Final[str] = "realcov-05a-model"
_CONTEXT_WINDOW: Final[int] = 64_000
_INSPECT_FUNCTION: Final[str] = "process.inspect_binary"
_FINAL_TEXT: Final[str] = "Analysis complete: the binary imports were collected."


class _RealBinaryAnalysisBridge(ToolBridgeBase):
    """Real bridge whose tool method parses a real binary with ``lief``.

    The bridge registers under :data:`ToolName.PROCESS` and exposes a single
    read-only ``inspect_binary`` method. When the orchestrator dispatches a
    tool call to it, the method parses the supplied binary path with the same
    ``lief`` pipeline the production orchestrator uses and returns the real
    imports and section names it discovers. ``inspect_binary`` is intentionally
    not in the process bridge's destructive method set so the orchestrator
    classifies it read-only and never gates it behind confirmation.
    """

    def __init__(self) -> None:
        """Initialize the bridge and its call ledger."""
        super().__init__()
        self.inspect_calls: list[str] = []

    @property
    @override
    def name(self) -> ToolName:
        """Return the tool name this bridge serves.

        Returns:
            ToolName: Always :data:`ToolName.PROCESS`.
        """
        return ToolName.PROCESS

    @property
    @override
    def tool_definition(self) -> ToolDefinition:
        """Return the advertised tool definition.

        Returns:
            ToolDefinition: A single read-only ``inspect_binary`` function that
                accepts a ``binary_path`` string argument.
        """
        return ToolDefinition(
            tool_name=ToolName.PROCESS,
            description="Read-only binary inspection backed by lief parsing.",
            functions=[
                ToolFunction(
                    name=_INSPECT_FUNCTION,
                    description="Parse a binary and report its imports and sections.",
                    parameters=[
                        ToolParameter(
                            name="binary_path",
                            type="string",
                            description="Absolute path to the binary to inspect.",
                        ),
                    ],
                    returns="dict",
                ),
            ],
        )

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """Mark the bridge ready without touching external tools.

        Args:
            tool_path: Ignored; this bridge has no external executable.
        """
        del tool_path
        self._state.connected = True
        self._state.tool_running = True

    @override
    async def shutdown(self) -> None:
        """Reset state and finalize shutdown."""
        self._state.connected = False
        self._state.tool_running = False
        await self._finalize_shutdown()

    @override
    async def is_available(self) -> bool:
        """Report availability.

        Returns:
            bool: Always ``True``; lief parsing needs no external tool.
        """
        return True

    def inspect_binary(self, binary_path: str) -> dict[str, object]:
        """Parse ``binary_path`` with ``lief`` and return real metadata.

        Args:
            binary_path: Absolute path to the binary to inspect.

        Returns:
            dict[str, object]: Real ``file_type``, ``architecture``, ``sha256``,
                imported function names, and section names parsed from the file.
        """
        self.inspect_calls.append(binary_path)
        info = _parse_real_binary(Path(binary_path))
        import_names: list[str] = [imp.function for imp in info.imports]
        section_names: list[str] = [sec.name for sec in info.sections]
        return {
            "file_type": info.file_type,
            "sha256": info.sha256,
            "imports": import_names,
            "sections": section_names,
        }


class _ScriptedProvider(LLMProviderBase):
    """Scripted LLM provider that drives a real two-turn agent loop.

    The provider is a stand-in for the remote model transport only: the harness
    has no reachable model endpoint. On the first ``chat`` it returns a real
    :class:`ToolCall` instructing the orchestrator to inspect a binary; after it
    observes the resulting tool message it returns a final text response. This
    exercises the orchestrator's real multi-turn loop, real tool dispatch, and
    real session persistence.
    """

    def __init__(self, *, binary_path: str) -> None:
        """Initialize the scripted provider.

        Args:
            binary_path: Path the emitted tool call asks the bridge to inspect.
        """
        super().__init__()
        self._binary_path = binary_path
        self.connected = True
        self.chat_call_count = 0
        self.observed_tool_result_message = False

    @property
    @override
    def name(self) -> ProviderName:
        """Return the provider name.

        Returns:
            ProviderName: Always :data:`ProviderName.OPENAI`.
        """
        return ProviderName.OPENAI

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Record credentials and mark the provider connected.

        Args:
            credentials: Placeholder credentials.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """List the single model this provider advertises.

        Returns:
            list[ModelInfo]: One model entry with a known context window.
        """
        return [
            ModelInfo(
                id=_MODEL_ID,
                name=_MODEL_ID,
                provider=ProviderName.OPENAI,
                context_window=_CONTEXT_WINDOW,
                supports_tools=True,
                supports_vision=False,
                supports_streaming=True,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            ),
        ]

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Return a tool call on the first turn and final text afterwards.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Returns:
            tuple[Message, list[ToolCall] | None]: On the first call, an
                assistant message plus a single real tool call. On subsequent
                calls, a final assistant text message with no tool calls.
        """
        del model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        self.chat_call_count += 1
        if any(message.role == "tool" for message in messages):
            self.observed_tool_result_message = True
        if self.chat_call_count == 1:
            assistant = Message(role="assistant", content="I will inspect the binary now.")
            call = ToolCall(
                id="realcov-05a-call-1",
                tool_name="process",
                function_name=_INSPECT_FUNCTION,
                arguments={"binary_path": self._binary_path},
            )
            return assistant, [call]
        return Message(role="assistant", content=_FINAL_TEXT), None

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Yield the final response text as a single chunk.

        Args:
            messages: Conversation history.
            model: Model id.
            tools: Tool definitions.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Yields:
            str: The final response content.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        yield _FINAL_TEXT

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return an empty provider-format tool list.

        Args:
            tools: Tool definitions.

        Returns:
            list[dict[str, object]]: Always empty; unused by this provider.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Return a passthrough provider-format message list.

        Args:
            messages: Message list.

        Returns:
            list[dict[str, object]]: Role/content dictionaries.
        """
        return [{"role": message.role, "content": message.content} for message in messages]


def _sha256_of(path: Path) -> str:
    """Compute the sha256 hex digest of a file on disk.

    Synchronous helper so async tests can compare against the orchestrator's
    own digest without invoking blocking ``pathlib`` I/O inside the coroutine.

    Args:
        path: Path to the file to hash.

    Returns:
        str: Hex-encoded sha256 digest of the file contents.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_orchestrator(
    tmp_path: Path,
    *,
    provider: LLMProviderBase | None = None,
    bridge: ToolBridgeBase | None = None,
    config: OrchestratorConfig | None = None,
) -> tuple[Orchestrator, SessionManager]:
    """Wire an orchestrator with a registered provider and optional bridge.

    Args:
        tmp_path: Pytest temporary directory for the session database.
        provider: Optional provider to register. Defaults to a connected
            scripted provider when omitted.
        bridge: Optional bridge to register with the tool registry.
        config: Optional orchestrator configuration.

    Returns:
        tuple[Orchestrator, SessionManager]: The orchestrator and its session
            manager (so tests can drive persistence assertions).
    """
    provider_registry = ProviderRegistry()
    if provider is not None:
        provider_registry.register(provider)

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    tool_registry = ToolRegistry(tools_dir=tools_dir)
    if bridge is not None:
        tool_registry.register_bridge(bridge.name, bridge)

    session_manager = SessionManager(
        store=SessionStore(db_path=tmp_path / "sessions.db"),
        auto_save=False,
    )
    orchestrator = Orchestrator(
        provider_registry=provider_registry,
        tool_registry=tool_registry,
        session_manager=session_manager,
        config=config or OrchestratorConfig(stream_responses=False, confirmation_level=ConfirmationLevel.NONE),
    )
    return orchestrator, session_manager


def _assert_real_pe_tool_result(tool_result: ToolResult) -> None:
    """Assert a tool result carries real PE metadata from the bridge.

    Validates every field of the tool-result payload against independently
    known properties of a real System32 PE DLL:

    * ``file_type`` must be ``"pe"`` (lief recognised the format).
    * ``imports`` must contain at least one name with ``"LoadLibrary"``
      (kernel32.dll exports this; any working Windows PE imports it or it
      is kernel32 itself, so this is always true for kernel32.dll).
    * ``sections`` must contain ``".text"`` (all real PE DLLs have a .text
      section; an empty list or a mangled section name fails here).
    * ``sha256`` must be a 64-character lowercase hex string (lief computed
      it from the real file, not from a stub).

    A broken bridge that returns an empty imports list, omits sections, or
    fabricates metadata will fail at least one of these assertions.

    Args:
        tool_result: The :class:`ToolResult` collected from the agent loop.
    """
    assert tool_result.success is True
    assert tool_result.duration_ms >= 0.0
    payload = tool_result.result
    assert isinstance(payload, dict)
    payload_dict = cast("dict[str, object]", payload)

    assert payload_dict["file_type"] == "pe", f"expected file_type='pe', got {payload_dict.get('file_type')!r}"

    imports = payload_dict["imports"]
    assert isinstance(imports, list), f"imports must be list, got {type(imports)}"
    import_names = cast("list[str]", imports)
    assert import_names, "imports list must not be empty for a real PE DLL"
    assert any("LoadLibrary" in name for name in import_names), (
        f"expected 'LoadLibrary' in at least one import name; got {import_names[:10]}"
    )

    sections = payload_dict["sections"]
    assert isinstance(sections, list), f"sections must be list, got {type(sections)}"
    section_names = cast("list[str]", sections)
    assert section_names, "sections list must not be empty for a real PE DLL"
    assert ".text" in section_names, f"expected '.text' in sections; got {section_names}"

    sha256 = payload_dict["sha256"]
    assert isinstance(sha256, str), f"sha256 must be str, got {type(sha256)}"
    assert len(sha256) == 64, f"sha256 must be 64 characters, got len={len(sha256)} for {sha256!r}"
    assert all(c in "0123456789abcdef" for c in sha256), f"sha256 must be lowercase hex digits only, got {sha256!r}"


@pytest.mark.asyncio
async def test_process_user_input_dispatches_real_tool_call_to_real_bridge(
    tmp_path: Path,
    real_pe_dll: Path,
) -> None:
    """End-to-end agent loop dispatches a real tool call producing real data.

    Args:
        tmp_path: Pytest temporary directory.
        real_pe_dll: Real System32 PE DLL fixture (kernel32.dll).
    """
    bridge = _RealBinaryAnalysisBridge()
    provider = _ScriptedProvider(binary_path=str(real_pe_dll))
    orch, session_manager = _build_orchestrator(tmp_path, provider=provider, bridge=bridge)

    captured_results: list[ToolResult] = []
    captured_calls: list[ToolCall] = []
    orch.set_tool_call_callback(captured_calls.append)
    orch.set_tool_result_callback(captured_results.append)

    session = await orch.start_session(provider=ProviderName.OPENAI, model=_MODEL_ID)

    await orch.process_user_input("inspect the binary and list its imports")

    assert provider.chat_call_count == 2
    assert provider.observed_tool_result_message is True
    assert bridge.inspect_calls == [str(real_pe_dll)]

    assert len(captured_calls) == 1
    assert captured_calls[0].function_name == _INSPECT_FUNCTION
    assert len(captured_results) == 1
    _assert_real_pe_tool_result(captured_results[0])

    assert orch.stats.total_tool_calls == 1
    assert orch.stats.successful_tool_calls == 1
    assert orch.stats.total_requests == 1

    roles_contents = [(msg.role, msg.content) for msg in session.messages]
    assert ("user", "inspect the binary and list its imports") in roles_contents
    assert ("assistant", _FINAL_TEXT) in roles_contents
    tool_messages = [msg for msg in session.messages if msg.role == "tool"]
    assert len(tool_messages) == 1
    assert tool_messages[0].tool_results is not None
    assert tool_messages[0].tool_results[0].success is True

    stored = session_manager.store.load(session.id)
    assert stored is not None
    stored_roles = [(msg.role, msg.content) for msg in stored.messages]
    assert ("user", "inspect the binary and list its imports") in stored_roles
    assert ("assistant", _FINAL_TEXT) in stored_roles


@pytest.mark.asyncio
async def test_add_binary_parses_real_pe_and_persists_session(
    tmp_path: Path,
    real_pe_dll: Path,
) -> None:
    """``add_binary`` loads a real PE, aggregates real data, and persists it.

    Args:
        tmp_path: Pytest temporary directory.
        real_pe_dll: Real System32 PE DLL fixture (kernel32.dll).
    """
    provider = _ScriptedProvider(binary_path=str(real_pe_dll))
    orch, session_manager = _build_orchestrator(tmp_path, provider=provider)

    bridge_summaries: list[BridgeAnalysisSummary] = []
    orch.set_bridge_analysis_callback(bridge_summaries.append)

    session = await orch.start_session(provider=ProviderName.OPENAI, model=_MODEL_ID)

    binary_info = await orch.add_binary(real_pe_dll, run_bridge_analysis=True)

    expected_sha = _sha256_of(real_pe_dll)
    assert binary_info.sha256 == expected_sha
    assert binary_info.file_type == "pe"
    assert binary_info.is_64bit is True
    assert binary_info.entry_point > 0
    section_names = {sec.name for sec in binary_info.sections}
    assert ".text" in section_names
    import_funcs = {imp.function for imp in binary_info.imports}
    assert any("LoadLibrary" in name for name in import_funcs)

    assert session.active_binary is not None
    assert session.active_binary.sha256 == expected_sha

    assert len(bridge_summaries) == 1
    summary = bridge_summaries[0]
    summary_imports = {imp.function for imp in summary.imports}
    assert any("LoadLibrary" in name for name in summary_imports)
    cached = orch.get_current_bridge_analysis(real_pe_dll.name)
    assert cached is not None

    stored = session_manager.store.load(session.id)
    assert stored is not None
    assert stored.active_binary is not None
    assert stored.active_binary.sha256 == expected_sha
    stored_sections = {sec.name for sec in stored.active_binary.sections}
    assert ".text" in stored_sections


@pytest.mark.asyncio
async def test_start_session_with_binary_path_loads_real_elf(
    tmp_path: Path,
    real_elf_binary: Path,
) -> None:
    """``start_session(binary_path=...)`` loads and parses a real ELF binary.

    Args:
        tmp_path: Pytest temporary directory.
        real_elf_binary: Committed real ELF corpus fixture.
    """
    provider = _ScriptedProvider(binary_path=str(real_elf_binary))
    orch, _session_manager = _build_orchestrator(tmp_path, provider=provider)

    session = await orch.start_session(
        provider=ProviderName.OPENAI,
        model=_MODEL_ID,
        binary_path=real_elf_binary,
        name="ELF analysis",
        description="Inspect the committed ELF corpus binary.",
    )

    assert session.name == "ELF analysis"
    assert session.notes == "Inspect the committed ELF corpus binary."
    assert session.active_binary is not None
    active = session.active_binary
    assert active.file_type == "elf"
    expected_sha = _sha256_of(real_elf_binary)
    assert active.sha256 == expected_sha
    assert active.entry_point > 0
    assert active.is_64bit is True

    prompt = orch.build_system_prompt()
    assert active.name in prompt
    assert "elf" in prompt


@pytest.mark.asyncio
async def test_session_add_binary_and_message_roundtrip_through_store(
    tmp_path: Path,
    real_pe_exe: Path,
) -> None:
    """``Session.add_binary`` / ``add_message`` persist and reload intact.

    Args:
        tmp_path: Pytest temporary directory.
        real_pe_exe: Real System32 PE executable fixture.
    """
    store = SessionStore(db_path=tmp_path / "sessions.db")
    manager = SessionManager(store=store, auto_save=False)

    session = await manager.create(provider=ProviderName.OPENAI, model=_MODEL_ID)

    info = _parse_real_binary(real_pe_exe)
    session.add_binary(info)
    session.add_message(Message(role="user", content="What does this executable import?"))
    session.add_message(Message(role="assistant", content="It imports several kernel32 functions."))

    await manager.update(session)

    reloaded = await manager.load(session.id)
    assert reloaded is not None
    assert manager.current is not None
    assert manager.current.id == session.id

    assert reloaded.active_binary is not None
    assert reloaded.active_binary.sha256 == info.sha256
    assert reloaded.active_binary.file_type == "pe"
    reloaded_sections = {sec.name for sec in reloaded.active_binary.sections}
    assert ".text" in reloaded_sections

    reloaded_contents = [(msg.role, msg.content) for msg in reloaded.messages]
    assert ("user", "What does this executable import?") in reloaded_contents
    assert ("assistant", "It imports several kernel32 functions.") in reloaded_contents


@pytest.mark.asyncio
async def test_message_callback_fires_for_user_and_assistant_messages(
    tmp_path: Path,
    real_pe_dll: Path,
) -> None:
    """The message callback observes the real user and assistant turn messages.

    Args:
        tmp_path: Pytest temporary directory.
        real_pe_dll: Real System32 PE DLL fixture (kernel32.dll).
    """
    bridge = _RealBinaryAnalysisBridge()
    provider = _ScriptedProvider(binary_path=str(real_pe_dll))
    orch, _session_manager = _build_orchestrator(tmp_path, provider=provider, bridge=bridge)

    observed: list[Message] = []
    orch.set_message_callback(observed.append)

    await orch.start_session(provider=ProviderName.OPENAI, model=_MODEL_ID)
    await orch.process_user_input("inspect this binary")

    observed_pairs = [(msg.role, msg.content) for msg in observed]
    assert ("user", "inspect this binary") in observed_pairs
    assert ("assistant", _FINAL_TEXT) in observed_pairs
    assistant_intermediate = [msg for msg in observed if msg.role == "assistant" and msg.content == "I will inspect the binary now."]
    assert len(assistant_intermediate) == 1
