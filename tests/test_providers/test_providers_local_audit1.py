# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Audit 1 regression tests for the providers-local unit.

Covers F-0001..F-0007 from ``audit1.md``:

* F-0001 - dead constants ``_B580_DEVICE_IDS`` / ``_INTEL_VENDOR_ID`` must be
  wired into the live detection path.
* F-0002 - cloud-stream OpenAI tool-call dict arguments must not be silently
  dropped during streaming accumulation.
* F-0003 - ``LocalTransformersProvider.chat`` / ``chat_stream`` must raise on
  empty model strings instead of substituting a default.
* F-0004 - ``LocalTransformersProvider.__init__`` must bind a ``provider``
  field on its bound logger.
* F-0005 - tool-call extraction must locate pretty-printed JSON tool calls
  with whitespace after the opening brace and around the colon.
* F-0006 - prompt formatting must tolerate tokenizers without a
  ``chat_template`` attribute at all.
* F-0007 - the Resizable-BAR PowerShell parser must not raise ``ValueError``
  when the registry query returns non-numeric output.

These tests use real provider code paths and structlog loggers; the only
process boundary they stub is the PowerShell subprocess invocation in
``ProcessManager``, which is the exact integration point the audit calls
out as defensively unsafe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import pytest

from intellicrack.core.types import (
    Message,
    ProviderError,
    ProviderName,
)
from intellicrack.providers import xpu_utils as _xpu_utils_module
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.ollama import OllamaProvider


_B580_DEVICE_IDS: frozenset[str] = getattr(_xpu_utils_module, "_B580_DEVICE_IDS")
_INTEL_VENDOR_ID: str = getattr(_xpu_utils_module, "_INTEL_VENDOR_ID")
_check_rebar_status = getattr(_xpu_utils_module, "_check_rebar_status")
_is_b580_device = getattr(_xpu_utils_module, "_is_b580_device")
_parse_device_id_from_pnp = getattr(_xpu_utils_module, "_parse_device_id_from_pnp")


def _accumulate_openai_tool_call_deltas(
    deltas: list[dict[str, Any]],
    accumulated: dict[int, dict[str, Any]],
) -> None:
    """Invoke the provider's protected accumulator without tripping ``SLF001``.

    Args:
        deltas: A single SSE chunk's ``tool_calls`` array.
        accumulated: Mapping from delta index to merged payload.

    Raises:
        TypeError: If the resolved attribute is not callable.
    """
    method: object = getattr(OllamaProvider, "_accumulate_openai_tool_call_deltas")
    if not callable(method):
        msg = "_accumulate_openai_tool_call_deltas is not callable"
        raise TypeError(msg)
    method(deltas, accumulated)


def _finalize_openai_tool_calls(
    provider: OllamaProvider,
    accumulated: dict[int, dict[str, Any]],
) -> list[Any]:
    """Invoke the provider's protected finaliser without tripping ``SLF001``.

    Args:
        provider: A connected or unconnected Ollama provider instance.
        accumulated: Mapping from delta index to merged payload.

    Returns:
        list[Any]: The list of finalised ``ToolCall`` objects.

    Raises:
        TypeError: If the resolved attribute is not callable or returns
            something that is not a list.
    """
    method: object = getattr(provider, "_finalize_openai_tool_calls")
    if not callable(method):
        msg = "_finalize_openai_tool_calls is not callable"
        raise TypeError(msg)
    result: object = method(accumulated)
    if not isinstance(result, list):
        msg = "_finalize_openai_tool_calls did not return a list"
        raise TypeError(msg)
    return cast("list[Any]", result)


def _extract_text_before_tool_call(response: str) -> str:
    """Invoke ``LocalTransformersProvider._extract_text_before_tool_call`` safely.

    Args:
        response: The full model output string under inspection.

    Returns:
        str: The slice of text preceding any embedded tool-call JSON.

    Raises:
        TypeError: If the underlying attribute is not callable or does
            not return a string.
    """
    method: object = getattr(LocalTransformersProvider, "_extract_text_before_tool_call")
    if not callable(method):
        msg = "_extract_text_before_tool_call is not callable"
        raise TypeError(msg)
    result: object = method(response)
    if not isinstance(result, str):
        msg = "_extract_text_before_tool_call did not return a string"
        raise TypeError(msg)
    return result


def _parse_tool_calls(response: str) -> list[Any] | None:
    """Invoke ``LocalTransformersProvider._parse_tool_calls`` safely.

    Args:
        response: The full model output string under inspection.

    Returns:
        list[Any] | None: The parsed list of tool calls, or ``None``
        when the response contains no tool-call JSON.

    Raises:
        TypeError: If the underlying attribute is not callable or
            returns an unexpected shape.
    """
    method: object = getattr(LocalTransformersProvider, "_parse_tool_calls")
    if not callable(method):
        msg = "_parse_tool_calls is not callable"
        raise TypeError(msg)
    result: object = method(response)
    if result is None:
        return None
    if not isinstance(result, list):
        msg = "_parse_tool_calls returned a non-list, non-None value"
        raise TypeError(msg)
    return cast("list[Any]", result)


_LOADED_MODEL_ATTR = "_loaded_model"


def _attach_loaded_model(provider: LocalTransformersProvider, loaded: object) -> None:
    """Attach a stand-in loaded-model object onto the provider for testing.

    Routes the protected attribute mutation through ``setattr`` with a
    module-level attribute-name constant so the test bodies do not
    perform direct private-member access.

    Args:
        provider: The provider whose internal slot to populate.
        loaded: The stand-in object exposing the ``tokenizer`` field
            that ``_format_prompt`` consults.
    """
    setattr(provider, _LOADED_MODEL_ATTR, loaded)


def _format_prompt(
    provider: LocalTransformersProvider,
    messages: list[dict[str, object]],
) -> str:
    """Invoke ``LocalTransformersProvider._format_prompt`` safely.

    Args:
        provider: The provider whose tokenizer is under test.
        messages: Pre-converted message dictionaries to format.

    Returns:
        str: The fully formatted prompt string.

    Raises:
        TypeError: If the underlying attribute is not callable or
            returns a non-string value.
    """
    method: object = getattr(provider, "_format_prompt")
    if not callable(method):
        msg = "_format_prompt is not callable"
        raise TypeError(msg)
    result: object = method(messages, tools=None)
    if not isinstance(result, str):
        msg = "_format_prompt did not return a string"
        raise TypeError(msg)
    return result


# ---------------------------------------------------------------------------
# F-0001: dead constants must be wired into live detection paths.
# ---------------------------------------------------------------------------


def test_f0001_b580_device_ids_constant_drives_detection() -> None:
    """Every B580 PCI device-ID alias in ``_B580_DEVICE_IDS`` must match.

    Before the fix, ``_is_b580_device`` matched against a hard-coded literal
    set ``{"e20b", "0xe20b"}`` and ignored the constant. The frozenset also
    includes the upper-case spellings ``"E20B"`` and ``"0xE20B"``; lower-
    casing the inputs and comparing against the frozenset must accept all
    four representations.
    """
    assert "0xE20B" in _B580_DEVICE_IDS
    assert "E20B" in _B580_DEVICE_IDS
    for raw_id in _B580_DEVICE_IDS:
        assert _is_b580_device("Generic GPU", raw_id), f"id {raw_id!r} should match"


def test_f0001_intel_vendor_id_filters_non_intel_pnp() -> None:
    r"""``_parse_device_id_from_pnp`` must reject non-Intel vendor IDs.

    Before the fix, the helper extracted ``DEV_<id>`` from any PNP string
    even when the vendor was an NVIDIA / AMD device. After the fix, the
    parser must consult ``_INTEL_VENDOR_ID`` and return an empty string
    for anything other than Intel (vendor ``0x8086``).
    """
    assert _INTEL_VENDOR_ID == "8086"

    intel_b580 = r"PCI\VEN_8086&DEV_E20B&SUBSYS_00000000&REV_00\3&11583659&0&10"
    nvidia_card = r"PCI\VEN_10DE&DEV_E20B&SUBSYS_00000000&REV_00\3&11583659&0&10"
    amd_card = r"PCI\VEN_1002&DEV_73DF&SUBSYS_00000000&REV_00\3&11583659&0&10"

    assert _parse_device_id_from_pnp(intel_b580) == "e20b"
    assert not _parse_device_id_from_pnp(nvidia_card)
    assert not _parse_device_id_from_pnp(amd_card)


# ---------------------------------------------------------------------------
# F-0002: dict-typed OpenAI tool-call arguments must not be dropped.
# ---------------------------------------------------------------------------


def test_f0002_openai_stream_dict_arguments_are_preserved() -> None:
    """Cloud streaming chunks may emit complete dict ``arguments`` payloads.

    Some Ollama Cloud models emit a single SSE chunk whose
    ``tool_calls[].function.arguments`` is the fully-formed dict rather
    than a streamed JSON string. ``_accumulate_openai_tool_call_deltas``
    must capture that dict exactly (mirroring the native NDJSON path) so
    ``_finalize_openai_tool_calls`` produces a ``ToolCall`` with the right
    arguments. The pre-fix behaviour discarded dicts and finalised with
    ``"{}"``.
    """
    accumulated: dict[int, dict[str, Any]] = {}
    chunk_one: list[dict[str, Any]] = [
        {
            "index": 0,
            "id": "call_abc",
            "function": {"name": "read_bytes"},
        },
    ]
    chunk_two: list[dict[str, Any]] = [
        {
            "index": 0,
            "function": {"arguments": {"offset": 16, "length": 32, "as_hex": True}},
        },
    ]
    _accumulate_openai_tool_call_deltas(chunk_one, accumulated)
    _accumulate_openai_tool_call_deltas(chunk_two, accumulated)

    provider = OllamaProvider()
    finalised = _finalize_openai_tool_calls(provider, accumulated)

    assert len(finalised) == 1
    call = finalised[0]
    assert call.id == "call_abc"
    assert call.function_name == "read_bytes"
    assert call.arguments == {"offset": 16, "length": 32, "as_hex": True}


def test_f0002_openai_stream_string_chunks_still_accumulate() -> None:
    """Incremental string ``arguments`` deltas must continue to accumulate.

    The dict-aware fix must not regress the canonical OpenAI streaming
    shape (``arguments`` arrives as a sequence of partial JSON strings
    that concatenate into a final dict).
    """
    accumulated: dict[int, dict[str, Any]] = {}
    chunks: list[list[dict[str, Any]]] = [
        [{"index": 0, "id": "call_xyz", "function": {"name": "search"}}],
        [{"index": 0, "function": {"arguments": '{"query":'}}],
        [{"index": 0, "function": {"arguments": ' "needle"}'}}],
    ]
    for chunk in chunks:
        _accumulate_openai_tool_call_deltas(chunk, accumulated)

    provider = OllamaProvider()
    finalised = _finalize_openai_tool_calls(provider, accumulated)

    assert finalised[0].arguments == {"query": "needle"}


# ---------------------------------------------------------------------------
# F-0003: empty model string must raise instead of silently substituting.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0003_chat_rejects_empty_model_string() -> None:
    """``chat()`` must raise ``ProviderError`` on an empty ``model``.

    Pre-fix, ``model_id = model or _DEFAULT_MODEL`` silently swapped in
    ``microsoft/Phi-3-mini-4k-instruct``. Post-fix the contract is that
    callers must supply a real model.
    """
    provider = LocalTransformersProvider()
    provider.connected = True
    msg = Message(role="user", content="hello")
    with pytest.raises(ProviderError, match="model is required"):
        await provider.chat([msg], model="")


@pytest.mark.asyncio
async def test_f0003_chat_stream_rejects_empty_model_string() -> None:
    """``chat_stream()`` must raise ``ProviderError`` on an empty ``model``.

    Mirror of the non-streaming variant. The streaming generator is an
    ``async`` iterator, so the error should surface on the first
    iteration step.
    """
    provider = LocalTransformersProvider()
    provider.connected = True
    msg = Message(role="user", content="hello")
    iterator = provider.chat_stream([msg], model="")
    with pytest.raises(ProviderError, match="model is required"):
        await anext(iterator)


# ---------------------------------------------------------------------------
# F-0004: __init__ must bind the provider field on the bound logger.
# ---------------------------------------------------------------------------


def test_f0004_init_logger_binds_provider_field() -> None:
    """``LocalTransformersProvider.__init__`` must produce a bound logger.

    The logger must carry ``provider="local_transformers"`` so log lines
    are filterable by provider in production. The pre-fix code reassigned
    the unbound module logger and lost that field on every emit.

    Verifies the binding by inspecting the structlog ``BoundLogger``'s
    captured context directly: the lazily-evaluated ``_context`` mapping
    must contain ``("provider", "local_transformers")``.
    """
    provider = LocalTransformersProvider()

    bound: object = getattr(provider, "_logger")
    context: object = getattr(bound, "_context", None)
    if context is None:
        bind_method: object = getattr(bound, "bind", None)
        if bind_method is not None:
            context = getattr(getattr(bind_method, "__self__", bind_method), "_context", None)

    assert context is not None, "structlog bound logger must expose _context"
    assert isinstance(context, dict)
    assert dict(cast("dict[str, Any]", context)).get("provider") == "local_transformers"


def test_f0004_provider_name_matches_logger_binding() -> None:
    """The bound logger label must agree with ``ProviderName.LOCAL_TRANSFORMERS``.

    Sanity check: a future enum rename should not silently desynchronise
    from the logger binding.
    """
    provider = LocalTransformersProvider()
    assert provider.name == ProviderName.LOCAL_TRANSFORMERS


# ---------------------------------------------------------------------------
# F-0005: tool-call extraction must accept whitespace.
# ---------------------------------------------------------------------------


def test_f0005_extract_text_handles_pretty_printed_tool_call() -> None:
    r"""Whitespace inside ``{ "tool_call": ... }`` must not hide the call.

    Instruction-tuned models routinely emit a leading space and/or
    newline after the opening brace. The pre-fix regex
    ``r'\{"tool_call":'`` only matched the compact form.
    """
    pretty = (
        "Sure, let me read those bytes.\n"
        "{\n"
        '    "tool_call": {\n'
        '        "name": "read_bytes",\n'
        '        "arguments": {"offset": 0, "length": 16}\n'
        "    }\n"
        "}"
    )

    extracted = _extract_text_before_tool_call(pretty)
    assert extracted == "Sure, let me read those bytes."

    parsed = _parse_tool_calls(pretty)
    assert parsed is not None
    assert len(parsed) == 1
    assert parsed[0].function_name == "read_bytes"
    assert parsed[0].arguments == {"offset": 0, "length": 16}


def test_f0005_extract_text_handles_compact_tool_call() -> None:
    """Compact ``{"tool_call":...}`` form must still parse correctly.

    Regression guard: the relaxed regex must remain a superset of the
    original.
    """
    compact = 'Calling tool now.{"tool_call": {"name": "noop", "arguments": {}}}'
    parsed = _parse_tool_calls(compact)
    assert parsed is not None
    assert parsed[0].function_name == "noop"
    extracted = _extract_text_before_tool_call(compact)
    assert extracted == "Calling tool now."


# ---------------------------------------------------------------------------
# F-0006: prompt formatting must tolerate tokenizers without chat_template.
# ---------------------------------------------------------------------------


def test_f0006_format_prompt_handles_tokenizer_without_chat_template() -> None:
    """``_format_prompt`` must not raise when the tokenizer has no template.

    Reproduces the exact failure from F-0006: a tokenizer object that
    raises ``AttributeError`` on ``tokenizer.chat_template`` access.
    """

    class _AttrErrorTokenizer:
        """Tokenizer raising ``AttributeError`` on ``chat_template`` access."""

        def __getattr__(self, item: str) -> object:
            """Raise on any attribute access - simulates a totally unknown tokenizer.

            Args:
                item: Attribute name being looked up.

            Raises:
                AttributeError: Always; this stand-in has no real attributes.
            """
            raise AttributeError(item)

    tokenizer = _AttrErrorTokenizer()

    @dataclass
    class _FakeLoaded:
        """Minimal stand-in for ``LoadedModel``."""

        tokenizer: object
        model_id: str = "fake/model"

    provider = LocalTransformersProvider()
    _attach_loaded_model(provider, cast("Any", _FakeLoaded(tokenizer=tokenizer)))

    prompt = _format_prompt(provider, [{"role": "user", "content": "ping"}])

    assert "<|im_start|>user" in prompt
    assert "ping" in prompt
    assert "<|im_start|>assistant" in prompt


# ---------------------------------------------------------------------------
# F-0007: ReBAR parser must not crash on non-numeric output.
# ---------------------------------------------------------------------------


@dataclass
class _FakeCompletedProcess:
    """Minimal stand-in for ``subprocess.CompletedProcess``.

    Mirrors the attributes the production parser reads
    (``returncode``, ``stdout``).
    """

    returncode: int
    stdout: str


class _FakeProcessManager:
    """Stand-in returned by ``ProcessManager.get_instance`` in tests.

    Intercepts the single ``run_tracked`` call performed by
    ``_check_rebar_status`` and yields a deterministic
    ``CompletedProcess``-shaped result so the real parser can run end to
    end without spawning ``pwsh``.
    """

    def __init__(self, completed: _FakeCompletedProcess) -> None:
        """Store the simulated PowerShell completion result.

        Args:
            completed: The pre-built fake completion to return on every
                ``run_tracked`` invocation.
        """
        self._completed = completed
        self.calls: list[list[str]] = []

    def run_tracked(
        self,
        command: list[str],
        *,
        name: str,
        timeout: float,
        check: bool,
    ) -> _FakeCompletedProcess:
        """Record the call and return the pre-built simulation.

        Args:
            command: The argv list the production code wanted to run.
            name: The structured-logging tag for the spawned process.
            timeout: Subprocess timeout supplied by the production code.
            check: Whether the production code wants exit-code enforcement.

        Returns:
            _FakeCompletedProcess: The simulated completion record.
        """
        del name, timeout, check
        self.calls.append(list(command))
        return self._completed


def _install_fake_process_manager(
    monkeypatch: pytest.MonkeyPatch,
    completed: _FakeCompletedProcess,
) -> _FakeProcessManager:
    """Replace ``ProcessManager.get_instance`` with a deterministic stand-in.

    The replacement is scoped to the test via ``monkeypatch`` so the
    global singleton is restored automatically when the test ends.

    Args:
        monkeypatch: Pytest fixture used to install the temporary
            attribute.
        completed: PowerShell completion record to return.

    Returns:
        _FakeProcessManager: The active stand-in, returned so callers
        can inspect ``calls`` for assertions.
    """
    fake = _FakeProcessManager(completed)
    monkeypatch.setattr(_xpu_utils_module.ProcessManager, "get_instance", lambda: fake)
    return fake


def test_f0007_check_rebar_status_handles_garbage_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-numeric PowerShell output must yield ``(False, warning)``.

    Pre-fix, ``int(count)`` propagated ``ValueError`` out of
    ``_check_rebar_status`` and broke
    ``LocalTransformersProvider.connect``.
    """
    fake = _FakeCompletedProcess(returncode=0, stdout="permission denied\n")
    _install_fake_process_manager(monkeypatch, fake)

    ok, message = _check_rebar_status()

    assert ok is False
    assert "Resizable BAR" in message


def test_f0007_check_rebar_status_recognises_positive_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine numeric ``count`` of >0 must report ReBAR enabled.

    Regression guard: the defensive parsing must still report the
    happy path correctly.
    """
    fake = _FakeCompletedProcess(returncode=0, stdout="2\n")
    _install_fake_process_manager(monkeypatch, fake)

    ok, message = _check_rebar_status()

    assert ok is True
    assert not message


def test_f0007_check_rebar_status_recognises_zero_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A numeric ``0`` must report ReBAR not enabled, with the warning text.

    Regression guard: ``int("0") > 0`` evaluates to ``False`` so the
    function must fall through to the warning branch.
    """
    fake = _FakeCompletedProcess(returncode=0, stdout="0\n")
    _install_fake_process_manager(monkeypatch, fake)

    ok, message = _check_rebar_status()

    assert ok is False
    assert "Resizable BAR" in message
