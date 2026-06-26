# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ScriptTypeInfo audit3 F-0006 remediation.

Verifies that the x64dbg template emits a coherent, runnable bypass skeleton:
no contradictory bp+bpcnd combination, every directive is a known x64dbg
command, and placeholders interpolate cleanly.
"""

from __future__ import annotations

from typing import Final

import pytest

from intellicrack.ui.panels.script_manager import ScriptTypeInfo


# Recognised x64dbg commands that may appear at the start of a script line.
# Sourced from the x64dbg command reference (https://help.x64dbg.com/en/latest/commands/).
_X64DBG_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "bp",
        "bpx",
        "bpd",
        "bpc",
        "bpcnd",
        "bphwc",
        "bphwd",
        "bphws",
        "bpgoto",
        "bplist",
        "bpgi",
        "bpge",
        "bpgc",
        "bpe",
        "bpdll",
        "bpdllc",
        "bpdlld",
        "bpdlle",
        "go",
        "run",
        "erun",
        "ergo",
        "estep",
        "esto",
        "estepi",
        "estepo",
        "stop",
        "pause",
        "step",
        "stepin",
        "stepout",
        "stepover",
        "sti",
        "sto",
        "skip",
        "ret",
        "log",
        "msg",
        "msgyn",
        "print",
        "scriptload",
        "scriptcmd",
        "scriptlog",
        "comment",
        "commentlist",
        "commentdel",
        "label",
        "labellist",
        "labeldel",
        "bookmark",
        "bookmarklist",
        "bookmarkdel",
        "find",
        "findall",
        "findasm",
        "findallmem",
        "ref",
        "refadd",
        "reffind",
        "refinit",
        "memcopy",
        "memset",
        "memmap",
        "alloc",
        "free",
        "loadlib",
        "freelib",
        "init",
        "attach",
        "detach",
        "setjit",
        "getjit",
        "disasm",
        "dis",
        "d",
        "dd",
        "dq",
        "dw",
        "db",
        "asm",
        "setregval",
        "getregval",
        "setbreakpointlog",
        "setbreakpointcommand",
        "setbreakpointcondition",
        "setbreakpointname",
        "setbreakpointlogcondition",
        "setbreakpointcommandcondition",
        "setbreakpointfastresume",
        "setbreakpointsingleshoot",
        "setbreakpointsilent",
        "sethardwarebreakpointname",
        "sethardwarebreakpointcondition",
        "sethardwarebreakpointlog",
        "sethardwarebreakpointlogcondition",
        "sethardwarebreakpointcommand",
        "sethardwarebreakpointcommandcondition",
        "sethardwarebreakpointfastresume",
        "sethardwarebreakpointsingleshoot",
        "sethardwarebreakpointsilent",
        "setmembreakpointname",
        "setmembreakpointcondition",
        "setmembreakpointlog",
        "setmembreakpointlogcondition",
        "setmembreakpointcommand",
        "setmembreakpointcommandcondition",
        "setmembreakpointfastresume",
        "setmembreakpointsingleshoot",
        "setmembreakpointsilent",
        "setdllbreakpointname",
        "setdllbreakpointcondition",
        "setdllbreakpointlog",
        "setdllbreakpointlogcondition",
        "setdllbreakpointcommand",
        "setdllbreakpointcommandcondition",
        "setdllbreakpointfastresume",
        "setdllbreakpointsingleshoot",
        "setdllbreakpointsilent",
        "setexceptionbreakpointname",
        "setexceptionbreakpointcondition",
        "setexceptionbreakpointlog",
        "setexceptionbreakpointlogcondition",
        "setexceptionbreakpointcommand",
        "setexceptionbreakpointcommandcondition",
        "setexceptionbreakpointfastresume",
        "setexceptionbreakpointsingleshoot",
        "setexceptionbreakpointsilent",
        "exit",
    },
)

# Register-assignment lines like ``eax=1``; the parser splits on `=` and matches
# the bare register name against this set.
_X64DBG_REGISTERS: Final[frozenset[str]] = frozenset(
    {
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "esp",
        "eip",
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "rip",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "ax",
        "bx",
        "cx",
        "dx",
        "al",
        "ah",
        "bl",
        "bh",
        "cl",
        "ch",
        "dl",
        "dh",
        "cf",
        "pf",
        "af",
        "zf",
        "sf",
        "tf",
        "if",
        "df",
        "of",
    },
)


def _strip_comment(line: str) -> str:
    """Strip an x64dbg ``//`` line comment.

    Args:
        line: A single source line.

    Returns:
        str: The line with any trailing ``//...`` comment removed and surrounding whitespace stripped.
    """
    idx = line.find("//")
    if idx >= 0:
        line = line[:idx]
    return line.strip()


def _classify_directive(line: str) -> str | None:
    """Classify the leading token of an x64dbg script line.

    Args:
        line: A non-empty, comment-stripped script line.

    Returns:
        str | None: A canonical directive identifier (lower-case command
        keyword, or ``"register-assign"`` for register writes), or None if
        the line cannot be classified.
    """
    head = line.lstrip()
    if not head:
        return None
    eq_idx = head.find("=")
    space_idx = head.find(" ")
    comma_idx = head.find(",")
    if eq_idx >= 0 and (space_idx < 0 or eq_idx < space_idx) and (comma_idx < 0 or eq_idx < comma_idx):
        reg = head[:eq_idx].strip().lower()
        if reg in _X64DBG_REGISTERS:
            return "register-assign"
        return None
    token = head.lower() if space_idx < 0 else head[:space_idx].lower()
    if token in _X64DBG_COMMANDS:
        return token
    return None


class TestX64dbgTemplateParse:
    """Audit3 F-0006: x64dbg template must be a coherent, parsable script."""

    @staticmethod
    @pytest.fixture
    def rendered() -> str:
        """Render the x64dbg template with concrete substitutions.

        Returns:
            str: The fully interpolated template text.
        """
        return ScriptTypeInfo.get_template("x64dbg", target="demo.exe", address="0x401000")

    @staticmethod
    def test_template_interpolates_address(rendered: str) -> None:
        """Address placeholder must be substituted into the template.

        Args:
            rendered: The fully interpolated x64dbg template text.
        """
        assert "0x401000" in rendered
        assert "{address}" not in rendered
        assert "{target}" not in rendered

    @staticmethod
    def test_template_has_no_contradictory_bp_and_bpcnd_override(rendered: str) -> None:
        """Audit3 F-0006: never both an unconditional bp AND an eax==1 bpcnd override.

        The pre-fix template emitted ``bp <addr>`` followed by
        ``bpcnd <addr>, "eax=1"`` which silently disabled the breakpoint
        before it could ever fire.

        Args:
            rendered: The fully interpolated x64dbg template text.
        """
        has_unconditional_bp = False
        has_bpcnd_eax1 = False
        for raw in rendered.splitlines():
            line = _strip_comment(raw)
            if not line:
                continue
            head = line.split(None, 1)
            if not head:
                continue
            cmd = head[0].lower()
            if cmd == "bp":
                has_unconditional_bp = True
            elif cmd == "bpcnd":
                rest = head[1] if len(head) > 1 else ""
                lowered = rest.replace(" ", "").lower()
                if "eax==1" in lowered or '"eax=1"' in lowered:
                    has_bpcnd_eax1 = True
        assert not (has_unconditional_bp and has_bpcnd_eax1), (
            'Template emits contradictory bp + bpcnd "eax==1" pair which prevents the breakpoint from firing'
        )

    @staticmethod
    def test_every_directive_is_recognised(rendered: str) -> None:
        """Every non-blank, non-comment line must be a recognised x64dbg directive.

        Args:
            rendered: The fully interpolated x64dbg template text.
        """
        unrecognised: list[str] = []
        for raw in rendered.splitlines():
            line = _strip_comment(raw)
            if not line:
                continue
            if _classify_directive(line) is None:
                unrecognised.append(line)
        assert not unrecognised, f"Unrecognised x64dbg directives in template: {unrecognised!r}"

    @staticmethod
    def test_template_starts_execution(rendered: str) -> None:
        """The template must end with an execution-starting directive.

        Args:
            rendered: The fully interpolated x64dbg template text.
        """
        directives: list[str] = []
        for raw in rendered.splitlines():
            line = _strip_comment(raw)
            if not line:
                continue
            classified = _classify_directive(line)
            if classified is not None:
                directives.append(classified)
        assert directives, "Template produced no classifiable directives"
        assert directives[-1] in {"run", "go", "erun", "ergo"}

    @staticmethod
    def test_template_installs_breakpoint(rendered: str) -> None:
        """The template must install a breakpoint of some kind.

        Args:
            rendered: The fully interpolated x64dbg template text.
        """
        directives: list[str] = []
        for raw in rendered.splitlines():
            line = _strip_comment(raw)
            if not line:
                continue
            classified = _classify_directive(line)
            if classified is not None:
                directives.append(classified)
        breakpoint_cmds = {"bp", "bpx", "bpcnd", "bphws"}
        assert any(d in breakpoint_cmds for d in directives), f"Template installs no breakpoint; directives = {directives!r}"


class TestScriptTypeInfoX64dbgMetadata:
    """Audit3 F-0006: x64dbg type metadata stays intact alongside the template fix."""

    @staticmethod
    def test_x64dbg_type_listed() -> None:
        """The x64dbg type must remain in the registered type list."""
        assert "x64dbg" in ScriptTypeInfo.get_types()

    @staticmethod
    def test_x64dbg_display_name() -> None:
        """The x64dbg display name must be stored explicitly in TYPES, not via fallback.

        The fallback in ``get_display_name`` returns the ``script_type`` argument
        when the ``'display'`` key is absent, so asserting only on the method
        return value cannot distinguish an explicitly configured display name from
        the silent fallback.  This test asserts the key exists in the TYPES dict
        directly, then verifies the method returns the stored value.
        """
        stored = ScriptTypeInfo.TYPES["x64dbg"]["display"]
        assert stored == "x64dbg"
        assert ScriptTypeInfo.get_display_name("x64dbg") == stored

    @staticmethod
    def test_x64dbg_extension() -> None:
        """The x64dbg extension must be the conventional .txt."""
        assert ScriptTypeInfo.get_extension("x64dbg") == ".txt"

    @staticmethod
    def test_x64dbg_language() -> None:
        """The x64dbg language identifier must be 'x64dbg'."""
        assert ScriptTypeInfo.get_language("x64dbg") == "x64dbg"
