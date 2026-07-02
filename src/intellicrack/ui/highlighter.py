# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Syntax highlighting for code display.

This module provides syntax highlighters for C/C++ decompiled code, x86/x64 assembly disassembly, and HexPat binary pattern definitions.
"""

from __future__ import annotations

from typing import ClassVar, override

from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import (
    QColor,
    QFont,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextDocument,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)

_BLOCK_STATE_NORMAL = 0
_BLOCK_STATE_DOUBLE_QUOTE = 1
_BLOCK_STATE_SINGLE_QUOTE = 2
_BLOCK_STATE_BLOCK_COMMENT = 1
_DELIM_STATE_MAP = (_BLOCK_STATE_DOUBLE_QUOTE, _BLOCK_STATE_SINGLE_QUOTE)

_STRING_DELIMITERS: tuple[str, ...] = ('"', "'", "`")


class HighlightRule:
    """A syntax highlighting rule."""

    __slots__ = ("format", "pattern")

    def __init__(self, pattern: str, text_format: QTextCharFormat) -> None:
        """Initialize the HighlightRule with a pattern and format.

        Args:
            pattern: Regular expression pattern to match.
            text_format: Text character format to apply to matches.
        """
        self.pattern = QRegularExpression(pattern)
        self.format = text_format


class _ThemedSyntaxHighlighter(QSyntaxHighlighter):
    """Base highlighter that resolves token colors from the active theme.

    Subclasses declare their language rules in :meth:`_setup_rules` using semantic token roles (``keyword``, ``string``, ``operator`` and so
    on) rather than hard-coded hex colors. The concrete color for each role is pulled from :meth:`ThemeManager.get_analysis_colors`, so
    tokens stay readable in both the light and dark themes. The highlighter subscribes to :attr:`ThemeManager.theme_changed` and re-resolves
    its palette and re-highlights the document whenever the theme switches.
    """

    _ROLE_KEYS: ClassVar[dict[str, str]] = {
        "keyword": "mnemonic_jump",
        "type": "operand_register",
        "string": "mnemonic_ret",
        "number": "operand_immediate",
        "function": "mnemonic_call",
        "comment": "muted",
        "meta": "warning",
        "operator": "foreground",
        "variable": "operand_memory",
    }

    def __init__(self, parent: QTextDocument | None = None) -> None:
        """Initialize the themed highlighter and subscribe to theme changes.

        Args:
            parent: Parent QTextDocument to highlight.
        """
        super().__init__(parent)
        self._rules: list[HighlightRule] = []
        self._rule_specs: list[tuple[str, str, bool, bool]] = []
        self._comment_role: str | None = None
        self._string_role: str | None = None
        self._multi_line_comment_format = QTextCharFormat()
        self._triple_quote_format = QTextCharFormat()
        self._comment_start = QRegularExpression(r"/\*")
        self._comment_end = QRegularExpression(r"\*/")
        self._theme_manager = ThemeManager.get_instance()
        self._palette: dict[str, QColor] = self._resolve_palette()
        self._theme_manager.theme_changed.connect(self._on_theme_changed)

    def _resolve_palette(self) -> dict[str, QColor]:
        """Resolve the semantic token palette from the active theme.

        Returns:
            dict[str, QColor]: Mapping of token role names to the theme's
                current QColor for that role.
        """
        colors = self._theme_manager.get_analysis_colors()
        return {role: QColor(colors[key]) for role, key in self._ROLE_KEYS.items()}

    def token_color(self, role: str) -> QColor:
        """Return the resolved foreground color for a semantic token role.

        Args:
            role: Token role name (e.g. ``"operator"`` or ``"number"``).

        Returns:
            QColor: The theme-resolved color currently used for that role.
        """
        return self._palette[role]

    def _create_format(
        self,
        role: str,
        *,
        bold: bool = False,
        italic: bool = False,
    ) -> QTextCharFormat:
        """Create a text format for a semantic token role.

        Args:
            role: Token role name resolved through the active theme palette.
            bold: Whether to use bold font.
            italic: Whether to use italic font.

        Returns:
            QTextCharFormat: Configured text format.
        """
        text_format = QTextCharFormat()
        text_format.setForeground(self._palette[role])
        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)
        return text_format

    def _setup_rules(self) -> None:
        """Rebuild highlighting rules and multi-line formats from the palette.

        Converts the language rule specifications collected in
        ``self._rule_specs`` into :class:`HighlightRule` objects using the
        current theme palette, and refreshes the multi-line comment and
        triple-quoted-string formats when the subclass declares those roles.
        """
        self._rules = [
            HighlightRule(pattern, self._create_format(role, bold=bold, italic=italic)) for pattern, role, bold, italic in self._rule_specs
        ]
        if self._comment_role is not None:
            self._multi_line_comment_format = self._create_format(self._comment_role, italic=True)
        if self._string_role is not None:
            self._triple_quote_format = self._create_format(self._string_role)

    def _on_theme_changed(self, _theme_name: str) -> None:
        """Re-resolve the palette and re-highlight after a theme switch.

        Args:
            _theme_name: Resolved theme name emitted by :class:`ThemeManager`
                (unused; colors are pulled from the manager directly).
        """
        self._palette = self._resolve_palette()
        self._setup_rules()
        self.rehighlight()

    def _apply_rules(self, text: str) -> None:
        """Apply every single-line highlighting rule to a block of text.

        Args:
            text: The text block to highlight.
        """
        for rule in self._rules:
            iterator = rule.pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), rule.format)

    @staticmethod
    def _line_comment_start_index(text: str) -> int:
        """Return the index of the first ``//`` line comment outside any string.

        Scans the text tracking single, double, and backtick string literals
        (honoring backslash escapes) so a ``//`` inside a string is not treated
        as a comment.

        Args:
            text: The text block to scan.

        Returns:
            int: Index of the opening ``//``, or ``-1`` when the line has no
                line comment outside a string literal.
        """
        in_string: str | None = None
        index = 0
        length = len(text)
        while index < length:
            char = text[index]
            if in_string is not None:
                if char == "\\":
                    index += 2
                    continue
                if char == in_string:
                    in_string = None
                index += 1
                continue
            if char in _STRING_DELIMITERS:
                in_string = char
                index += 1
                continue
            if char == "/" and index + 1 < length and text[index + 1] == "/":
                return index
            index += 1
        return -1

    @staticmethod
    def _guard_block_start(start_index: int, line_comment_index: int) -> int:
        """Discard a block-comment start that falls inside a line comment.

        Args:
            start_index: Candidate index of a ``/*`` block-comment opener, or
                ``-1`` when none was found.
            line_comment_index: Index of the line's ``//`` comment, or ``-1``.

        Returns:
            int: ``start_index`` when it precedes any line comment, otherwise
                ``-1`` so the ``/*`` inside a ``//`` comment is ignored.
        """
        if start_index >= 0 and 0 <= line_comment_index <= start_index:
            return -1
        return start_index

    def _scan_block_comments(self, text: str) -> None:
        """Highlight ``/* */`` block comments spanning one or more blocks.

        A ``/*`` that appears after a ``//`` line comment on the same line is
        ignored so a commented-out ``/*`` does not start a spurious multi-line
        block comment.

        Args:
            text: The text block to highlight.
        """
        self.setCurrentBlockState(_BLOCK_STATE_NORMAL)
        line_comment_index = self._line_comment_start_index(text)

        if self.previousBlockState() == _BLOCK_STATE_BLOCK_COMMENT:
            start_index = 0
        else:
            match = self._comment_start.match(text)
            candidate = match.capturedStart() if match.hasMatch() else -1
            start_index = self._guard_block_start(candidate, line_comment_index)

        while start_index >= 0:
            end_match = self._comment_end.match(text, start_index)
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                comment_length = end_index - start_index
                self.setCurrentBlockState(_BLOCK_STATE_NORMAL)
            else:
                self.setCurrentBlockState(_BLOCK_STATE_BLOCK_COMMENT)
                comment_length = len(text) - start_index

            self.setFormat(start_index, comment_length, self._multi_line_comment_format)

            next_match = self._comment_start.match(text, start_index + comment_length)
            candidate = next_match.capturedStart() if next_match.hasMatch() else -1
            start_index = self._guard_block_start(candidate, line_comment_index)


class CSyntaxHighlighter(_ThemedSyntaxHighlighter):
    """Syntax highlighter for C/C++ code.

    Highlights keywords, types, strings, numbers, comments,
    and function calls in decompiled C code.

    Attributes:
        KEYWORDS: C/C++ reserved keyword strings for syntax highlighting.
        TYPES: C/C++ type names including Windows SDK types for highlighting.
    """

    KEYWORDS: ClassVar[tuple[str, ...]] = (
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "int",
        "long",
        "register",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "bool",
        "true",
        "false",
        "nullptr",
        "class",
        "public",
        "private",
        "protected",
        "virtual",
        "inline",
        "template",
        "typename",
        "namespace",
        "using",
        "try",
        "catch",
        "throw",
        "new",
        "delete",
        "this",
        "operator",
    )

    TYPES: ClassVar[tuple[str, ...]] = (
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "size_t",
        "ssize_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
        "BYTE",
        "WORD",
        "DWORD",
        "QWORD",
        "BOOL",
        "HANDLE",
        "LPVOID",
        "LPCSTR",
        "LPWSTR",
        "HMODULE",
        "FARPROC",
        "HRESULT",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
    )

    def __init__(self, parent: QTextDocument | None = None) -> None:
        """Initialize the CSyntaxHighlighter with C/C++ highlighting rules.

        Args:
            parent: Parent QTextDocument to highlight.
        """
        super().__init__(parent)
        self._comment_role = "comment"
        self._rule_specs = [
            *((rf"\b{keyword}\b", "keyword", True, False) for keyword in self.KEYWORDS),
            *((rf"\b{type_name}\b", "type", False, False) for type_name in self.TYPES),
            (r'"[^"\\]*(\\.[^"\\]*)*"', "string", False, False),
            (r"'[^'\\]*(\\.[^'\\]*)*'", "string", False, False),
            (r"\b0x[0-9A-Fa-f]+\b", "number", False, False),
            (r"\b0b[01]+\b", "number", False, False),
            (r"\b\d+\.?\d*[fFlL]?\b", "number", False, False),
            (r"\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()", "function", False, False),
            (r"//[^\n]*", "comment", False, True),
            (r"#\s*\w+", "meta", False, False),
            (r"[+\-*/%&|^~<>=!]+", "operator", False, False),
        ]
        self._setup_rules()

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        self._apply_rules(text)
        self._scan_block_comments(text)


class AssemblySyntaxHighlighter(_ThemedSyntaxHighlighter):
    """Syntax highlighter for x86/x64 assembly.

    Highlights instructions, registers, addresses, and comments
    in disassembly output.

    Attributes:
        INSTRUCTIONS: Recognized x86/x64 instruction mnemonics.
        REGISTERS: Recognized CPU register names.
        MEMORY_KEYWORDS: Recognized memory operand keywords.
    """

    INSTRUCTIONS: ClassVar[tuple[str, ...]] = (
        "mov",
        "movsx",
        "movzx",
        "movsxd",
        "lea",
        "push",
        "pop",
        "pushf",
        "popf",
        "call",
        "ret",
        "retn",
        "jmp",
        "je",
        "jne",
        "jz",
        "jnz",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jg",
        "jge",
        "jl",
        "jle",
        "jo",
        "jno",
        "js",
        "jns",
        "cmp",
        "test",
        "add",
        "sub",
        "mul",
        "imul",
        "div",
        "idiv",
        "inc",
        "dec",
        "and",
        "or",
        "xor",
        "not",
        "neg",
        "shl",
        "shr",
        "sal",
        "sar",
        "rol",
        "ror",
        "nop",
        "int",
        "syscall",
        "sysenter",
        "leave",
        "enter",
        "hlt",
        "wait",
        "cdq",
        "cwd",
        "cbw",
        "cwde",
        "cdqe",
        "cqo",
        "cmove",
        "cmovne",
        "cmova",
        "cmovae",
        "cmovb",
        "cmovbe",
        "cmovg",
        "cmovge",
        "cmovl",
        "cmovle",
        "sete",
        "setne",
        "seta",
        "setae",
        "setb",
        "setbe",
        "setg",
        "setge",
        "setl",
        "setle",
        "rep",
        "repe",
        "repne",
        "repz",
        "repnz",
        "movsb",
        "movsw",
        "movsd",
        "movsq",
        "stosb",
        "stosw",
        "stosd",
        "stosq",
        "lodsb",
        "lodsw",
        "lodsd",
        "lodsq",
        "scasb",
        "scasw",
        "scasd",
        "scasq",
        "xchg",
        "bswap",
        "xadd",
        "cmpxchg",
        "lock",
        "movaps",
        "movups",
        "movapd",
        "movupd",
        "movdqa",
        "movdqu",
        "movss",
        "movsd",
        "addps",
        "addpd",
        "addss",
        "addsd",
        "subps",
        "subpd",
        "subss",
        "subsd",
        "mulps",
        "mulpd",
        "mulss",
        "mulsd",
        "divps",
        "divpd",
        "divss",
        "divsd",
        "sqrtps",
        "sqrtss",
        "pand",
        "por",
        "pxor",
        "pshufb",
        "pshufd",
        "punpcklbw",
        "punpckhbw",
        "vmovaps",
        "vmovups",
        "vaddps",
        "vsubps",
        "vmulps",
        "vdivps",
        "vpand",
        "vpor",
        "vpxor",
        "vzeroupper",
        "vzeroall",
        "vbroadcastss",
        "vbroadcastsd",
        "vextractf128",
        "vinsertf128",
        "vperm2f128",
        "vpermilps",
        "kandw",
        "korw",
        "kxorw",
        "kmovw",
        "kunpckbw",
        "fld",
        "fst",
        "fstp",
        "fadd",
        "fsub",
        "fmul",
        "fdiv",
        "fxch",
        "fcom",
        "fcomp",
        "fcompp",
        "fucom",
        "fucomi",
        "fldcw",
        "fnstcw",
        "finit",
        "fninit",
        "fwait",
        "fnclex",
    )

    REGISTERS: ClassVar[tuple[str, ...]] = (
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
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "esp",
        "eip",
        "ax",
        "bx",
        "cx",
        "dx",
        "si",
        "di",
        "bp",
        "sp",
        "al",
        "bl",
        "cl",
        "dl",
        "ah",
        "bh",
        "ch",
        "dh",
        "sil",
        "dil",
        "bpl",
        "spl",
        "r8d",
        "r9d",
        "r10d",
        "r11d",
        "r12d",
        "r13d",
        "r14d",
        "r15d",
        "r8w",
        "r9w",
        "r10w",
        "r11w",
        "r12w",
        "r13w",
        "r14w",
        "r15w",
        "r8b",
        "r9b",
        "r10b",
        "r11b",
        "r12b",
        "r13b",
        "r14b",
        "r15b",
        "cs",
        "ds",
        "es",
        "fs",
        "gs",
        "ss",
        "xmm0",
        "xmm1",
        "xmm2",
        "xmm3",
        "xmm4",
        "xmm5",
        "xmm6",
        "xmm7",
        "xmm8",
        "xmm9",
        "xmm10",
        "xmm11",
        "xmm12",
        "xmm13",
        "xmm14",
        "xmm15",
        "ymm0",
        "ymm1",
        "ymm2",
        "ymm3",
        "ymm4",
        "ymm5",
        "ymm6",
        "ymm7",
        "ymm8",
        "ymm9",
        "ymm10",
        "ymm11",
        "ymm12",
        "ymm13",
        "ymm14",
        "ymm15",
        "zmm0",
        "zmm1",
        "zmm2",
        "zmm3",
        "zmm4",
        "zmm5",
        "zmm6",
        "zmm7",
        "zmm8",
        "zmm9",
        "zmm10",
        "zmm11",
        "zmm12",
        "zmm13",
        "zmm14",
        "zmm15",
        "zmm16",
        "zmm17",
        "zmm18",
        "zmm19",
        "zmm20",
        "zmm21",
        "zmm22",
        "zmm23",
        "zmm24",
        "zmm25",
        "zmm26",
        "zmm27",
        "zmm28",
        "zmm29",
        "zmm30",
        "zmm31",
        "k0",
        "k1",
        "k2",
        "k3",
        "k4",
        "k5",
        "k6",
        "k7",
        "st",
        "st0",
        "st1",
        "st2",
        "st3",
        "st4",
        "st5",
        "st6",
        "st7",
    )

    MEMORY_KEYWORDS: ClassVar[tuple[str, ...]] = (
        "byte",
        "word",
        "dword",
        "qword",
        "ptr",
        "offset",
    )

    def __init__(self, parent: QTextDocument | None = None) -> None:
        """Initialize the AssemblySyntaxHighlighter with assembly highlighting rules.

        Args:
            parent: Parent QTextDocument to highlight.
        """
        super().__init__(parent)
        self._rule_specs = [
            *((rf"\b{instr}\b", "keyword", True, False) for instr in self.INSTRUCTIONS),
            *((rf"\b{reg}\b", "variable", False, False) for reg in self.REGISTERS),
            *((rf"\b{mem_kw}\b", "type", False, False) for mem_kw in self.MEMORY_KEYWORDS),
            (r"^\s*\.(text|data|bss|section|globl?|extern)\b", "meta", False, False),
            (r"\b(db|dw|dd|dq|resb|resw|resd|resq)\b", "meta", False, False),
            (r"\b0x[0-9A-Fa-f]+\b", "number", False, False),
            (r"\b[0-9A-Fa-f]+h\b", "number", False, False),
            (r"\b\d+\b", "number", False, False),
            (r"^[A-Za-z_][A-Za-z0-9_]*:", "function", False, False),
            (r";.*$", "comment", False, True),
            (r'"[^"]*"', "string", False, False),
            (r"'[^']*'", "string", False, False),
        ]
        self._setup_rules()

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        self._apply_rules(text)


class PythonSyntaxHighlighter(_ThemedSyntaxHighlighter):
    """Syntax highlighter for Python code.

    Highlights Python keywords, built-ins, strings, numbers,
    and comments in Python scripts.

    Attributes:
        KEYWORDS: Python reserved keywords.
        BUILTINS: Python built-in function and type names.
    """

    KEYWORDS: ClassVar[tuple[str, ...]] = (
        "False",
        "None",
        "True",
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
    )

    BUILTINS: ClassVar[tuple[str, ...]] = (
        "abs",
        "all",
        "any",
        "bin",
        "bool",
        "bytes",
        "callable",
        "chr",
        "classmethod",
        "compile",
        "complex",
        "delattr",
        "dict",
        "dir",
        "divmod",
        "enumerate",
        "eval",
        "exec",
        "filter",
        "float",
        "format",
        "frozenset",
        "getattr",
        "globals",
        "hasattr",
        "hash",
        "help",
        "hex",
        "id",
        "input",
        "int",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "list",
        "locals",
        "map",
        "max",
        "memoryview",
        "min",
        "next",
        "object",
        "oct",
        "open",
        "ord",
        "pow",
        "print",
        "property",
        "range",
        "repr",
        "reversed",
        "round",
        "set",
        "setattr",
        "slice",
        "sorted",
        "staticmethod",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
        "vars",
        "zip",
    )

    def __init__(self, parent: QTextDocument | None = None) -> None:
        """Initialize the PythonSyntaxHighlighter with Python highlighting rules.

        Args:
            parent: Parent QTextDocument to highlight.
        """
        super().__init__(parent)
        self._string_role = "string"
        self._rule_specs = [
            *((rf"\b{keyword}\b", "keyword", True, False) for keyword in self.KEYWORDS),
            *((rf"\b{builtin}\b", "type", False, False) for builtin in self.BUILTINS),
            (r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)", "function", False, False),
            (r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", "function", False, False),
            (r'"[^"\\]*(\\.[^"\\]*)*"', "string", False, False),
            (r"'[^'\\]*(\\.[^'\\]*)*'", "string", False, False),
            (r"\b0x[0-9A-Fa-f]+\b", "number", False, False),
            (r"\b0b[01]+\b", "number", False, False),
            (r"\b0o[0-7]+\b", "number", False, False),
            (r"\b\d+\.?\d*\b", "number", False, False),
            (r"#[^\n]*", "comment", False, True),
            (r"@[A-Za-z_][A-Za-z0-9_]*", "meta", False, False),
            (r"\bself\b", "variable", False, False),
            (r"\bcls\b", "variable", False, False),
        ]
        self._setup_rules()

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        self._apply_rules(text)
        self._highlight_triple_quotes(text)

    def _highlight_triple_quotes(self, text: str) -> None:
        """Handle multi-line triple-quoted string highlighting.

        Uses QSyntaxHighlighter block state to track whether we are
        inside a triple-quoted string across lines.

        State encoding:
            -1 or 0: not inside a triple-quoted string
            1: inside a double-triple-quote block
            2: inside a single-triple-quote block

        Args:
            text: The text block to highlight.
        """
        delimiters = ('"""', "'''")
        prev_state = self.previousBlockState()
        offset = 0

        if prev_state == _BLOCK_STATE_DOUBLE_QUOTE:
            end_idx = text.find('"""', offset)
            if end_idx == -1:
                self.setFormat(0, len(text), self._triple_quote_format)
                self.setCurrentBlockState(_BLOCK_STATE_DOUBLE_QUOTE)
                return
            length = end_idx + 3
            self.setFormat(0, length, self._triple_quote_format)
            offset = length
        elif prev_state == _BLOCK_STATE_SINGLE_QUOTE:
            end_idx = text.find("'''", offset)
            if end_idx == -1:
                self.setFormat(0, len(text), self._triple_quote_format)
                self.setCurrentBlockState(_BLOCK_STATE_SINGLE_QUOTE)
                return
            length = end_idx + 3
            self.setFormat(0, length, self._triple_quote_format)
            offset = length

        self.setCurrentBlockState(_BLOCK_STATE_NORMAL)

        while offset < len(text):
            nearest_pos = -1
            nearest_delim_idx = -1

            for delim_idx, delim in enumerate(delimiters):
                pos = text.find(delim, offset)
                if pos != -1 and (nearest_pos == -1 or pos < nearest_pos):
                    nearest_pos = pos
                    nearest_delim_idx = delim_idx

            if nearest_pos == -1:
                break

            delim = delimiters[nearest_delim_idx]
            end_idx = text.find(delim, nearest_pos + 3)

            if end_idx == -1:
                self.setFormat(nearest_pos, len(text) - nearest_pos, self._triple_quote_format)
                state_value = _DELIM_STATE_MAP[nearest_delim_idx]
                self.setCurrentBlockState(state_value)
                return

            length = end_idx - nearest_pos + 3
            self.setFormat(nearest_pos, length, self._triple_quote_format)
            offset = nearest_pos + length


class JavaScriptSyntaxHighlighter(_ThemedSyntaxHighlighter):
    """Syntax highlighter for JavaScript code.

    Highlights JavaScript/Frida script keywords, functions,
    strings, numbers, and comments.

    Attributes:
        KEYWORDS: JavaScript reserved keywords.
        FRIDA_GLOBALS: Frida API global object names.
    """

    KEYWORDS: ClassVar[tuple[str, ...]] = (
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "of",
        "return",
        "static",
        "super",
        "switch",
        "this",
        "throw",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "true",
        "false",
        "null",
        "undefined",
    )

    FRIDA_GLOBALS: ClassVar[tuple[str, ...]] = (
        "Process",
        "Module",
        "Memory",
        "Interceptor",
        "NativeFunction",
        "NativeCallback",
        "NativePointer",
        "ptr",
        "NULL",
        "Thread",
        "Stalker",
        "DebugSymbol",
        "Instruction",
        "ObjC",
        "Java",
        "send",
        "recv",
        "console",
        "rpc",
        "Script",
        "Kernel",
        "Socket",
    )

    def __init__(self, parent: QTextDocument | None = None) -> None:
        """Initialize the JavaScriptSyntaxHighlighter with JavaScript highlighting rules.

        Args:
            parent: Parent QTextDocument to highlight.
        """
        super().__init__(parent)
        self._comment_role = "comment"
        self._rule_specs = [
            *((rf"\b{keyword}\b", "keyword", True, False) for keyword in self.KEYWORDS),
            *((rf"\b{frida_global}\b", "type", True, False) for frida_global in self.FRIDA_GLOBALS),
            (r"\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()", "function", False, False),
            (r'"[^"\\]*(\\.[^"\\]*)*"', "string", False, False),
            (r"'[^'\\]*(\\.[^'\\]*)*'", "string", False, False),
            (r"`[^`\\]*(\\.[^`\\]*)*`", "string", False, False),
            (r"\b0x[0-9A-Fa-f]+\b", "number", False, False),
            (r"\b\d+\.?\d*\b", "number", False, False),
            (r"//[^\n]*", "comment", False, True),
        ]
        self._setup_rules()

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        self._apply_rules(text)
        self._scan_block_comments(text)


class HexPatSyntaxHighlighter(_ThemedSyntaxHighlighter):
    """Syntax highlighter for the HexPat pattern definition language.

    Highlights keywords (structural, control flow, namespace), primitive types
    (including 128-bit and char16/str), endianness prefixes, annotations,
    strings, numbers, and comments in HexPat source code.

    Attributes:
        KEYWORDS: HexPat keywords for syntax highlighting.
        TYPES: HexPat primitive type names for syntax highlighting.
        ENDIANNESS: Endianness prefix keywords.
        BUILTINS: Built-in function names.
    """

    KEYWORDS: ClassVar[tuple[str, ...]] = (
        "struct",
        "union",
        "enum",
        "bitfield",
        "if",
        "else",
        "match",
        "while",
        "for",
        "fn",
        "return",
        "break",
        "continue",
        "namespace",
        "using",
        "in",
        "out",
        "ref",
        "null",
        "true",
        "false",
        "auto",
        "this",
        "parent",
        "try",
        "catch",
    )

    TYPES: ClassVar[tuple[str, ...]] = (
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "s8",
        "s16",
        "s32",
        "s64",
        "s128",
        "float",
        "double",
        "char",
        "char16",
        "bool",
        "str",
        "padding",
    )

    ENDIANNESS: ClassVar[tuple[str, ...]] = ("le", "be")

    BUILTINS: ClassVar[tuple[str, ...]] = ("sizeof", "addressof")

    def __init__(self, parent: QTextDocument | None = None) -> None:
        """Initialize the HexPatSyntaxHighlighter with HexPat pattern language highlighting rules.

        Args:
            parent: Parent QTextDocument to highlight.
        """
        super().__init__(parent)
        self._comment_role = "comment"
        self._rule_specs = [
            *((rf"\b{keyword}\b", "keyword", True, False) for keyword in self.KEYWORDS),
            *((rf"\b{type_name}\b", "type", False, False) for type_name in self.TYPES),
            *((rf"\b{endian_kw}\b", "meta", False, False) for endian_kw in self.ENDIANNESS),
            *((rf"\b{builtin_name}\b", "function", False, False) for builtin_name in self.BUILTINS),
            (r"\$", "function", False, False),
            (r"\[\[.*?\]\]", "meta", False, False),
            *((rf"\b{attr_kw}\b", "variable", False, False) for attr_kw in ("color", "validate", "description", "min", "max")),
            (r'"[^"\\]*(\\.[^"\\]*)*"', "string", False, False),
            (r"\b0x[0-9A-Fa-f]+\b", "number", False, False),
            (r"\b\d+\b", "number", False, False),
            (r"//[^\n]*", "comment", False, True),
            (r"[+\-*/%&|^~<>=!]+", "operator", False, False),
        ]
        self._setup_rules()

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        self._apply_rules(text)
        self._scan_block_comments(text)


def get_highlighter_for_language(
    language: str,
    parent: QTextDocument | None = None,
) -> QSyntaxHighlighter | None:
    """Get the appropriate syntax highlighter for a language.

    Args:
        language: Language name (c, cpp, asm, python, javascript, frida, hexpat, pattern, hexpattern).
        parent: Parent QTextDocument.

    Returns:
        QSyntaxHighlighter | None: Appropriate highlighter or None if not supported.
    """
    language_lower = language.lower()
    _logger.debug("highlighter_requested", language=language_lower)

    if language_lower in {"c", "cpp", "c++", "decompiled"}:
        return CSyntaxHighlighter(parent)
    if language_lower in {"asm", "assembly", "disassembly", "x86", "x64"}:
        return AssemblySyntaxHighlighter(parent)
    if language_lower in {"python", "py"}:
        return PythonSyntaxHighlighter(parent)
    if language_lower in {"javascript", "js", "frida"}:
        return JavaScriptSyntaxHighlighter(parent)
    if language_lower in {"hexpat", "pattern", "hexpattern"}:
        return HexPatSyntaxHighlighter(parent)
    return None
