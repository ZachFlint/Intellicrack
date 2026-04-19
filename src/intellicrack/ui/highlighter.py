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


_logger = get_logger("ui.highlighter")

_BLOCK_STATE_NORMAL = 0
_BLOCK_STATE_DOUBLE_QUOTE = 1
_BLOCK_STATE_SINGLE_QUOTE = 2
_DELIM_STATE_MAP = (_BLOCK_STATE_DOUBLE_QUOTE, _BLOCK_STATE_SINGLE_QUOTE)


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


class CSyntaxHighlighter(QSyntaxHighlighter):
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
        self._rules: list[HighlightRule] = []
        self._multi_line_comment_format = QTextCharFormat()
        self._comment_start = QRegularExpression(r"/\*")
        self._comment_end = QRegularExpression(r"\*/")
        self._setup_rules()

    @staticmethod
    def _create_format(
        color: str,
        *,
        bold: bool = False,
        italic: bool = False,
    ) -> QTextCharFormat:
        """Create a text format with specified style.

        Args:
            color: Hex color string.
            bold: Whether to use bold font.
            italic: Whether to use italic font.

        Returns:
            QTextCharFormat: Configured text format.
        """
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))
        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)
        return text_format

    def _setup_rules(self) -> None:
        """Set up all highlighting rules."""
        keyword_format = CSyntaxHighlighter._create_format("#569CD6", bold=True)
        for keyword in self.KEYWORDS:
            pattern = rf"\b{keyword}\b"
            self._rules.append(HighlightRule(pattern, keyword_format))

        type_format = CSyntaxHighlighter._create_format("#4EC9B0")
        for type_name in self.TYPES:
            pattern = rf"\b{type_name}\b"
            self._rules.append(HighlightRule(pattern, type_format))

        string_format = CSyntaxHighlighter._create_format("#CE9178")
        self._rules.append(HighlightRule(r'"[^"\\]*(\\.[^"\\]*)*"', string_format))
        self._rules.append(HighlightRule(r"'[^'\\]*(\\.[^'\\]*)*'", string_format))

        number_format = CSyntaxHighlighter._create_format("#B5CEA8")
        self._rules.append(HighlightRule(r"\b0x[0-9A-Fa-f]+\b", number_format))
        self._rules.append(HighlightRule(r"\b0b[01]+\b", number_format))
        self._rules.append(HighlightRule(r"\b\d+\.?\d*[fFlL]?\b", number_format))

        function_format = CSyntaxHighlighter._create_format("#DCDCAA")
        self._rules.append(HighlightRule(r"\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()", function_format))

        comment_format = CSyntaxHighlighter._create_format("#6A9955", italic=True)
        self._rules.append(HighlightRule(r"//[^\n]*", comment_format))
        self._multi_line_comment_format = comment_format

        preprocessor_format = CSyntaxHighlighter._create_format("#C586C0")
        self._rules.append(HighlightRule(r"#\s*\w+", preprocessor_format))

        operator_format = CSyntaxHighlighter._create_format("#D4D4D4")
        self._rules.append(HighlightRule(r"[+\-*/%&|^~<>=!]+", operator_format))

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        for rule in self._rules:
            iterator = rule.pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    rule.format,
                )

        self.setCurrentBlockState(0)

        start_index = 0
        if self.previousBlockState() != 1:
            match = self._comment_start.match(text)
            start_index = match.capturedStart() if match.hasMatch() else -1

        while start_index >= 0:
            end_match = self._comment_end.match(text, start_index)
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                comment_length = end_index - start_index
                self.setCurrentBlockState(0)
            else:
                self.setCurrentBlockState(1)
                comment_length = len(text) - start_index

            self.setFormat(
                start_index,
                comment_length,
                self._multi_line_comment_format,
            )

            next_match = self._comment_start.match(text, start_index + comment_length)
            start_index = next_match.capturedStart() if next_match.hasMatch() else -1


class AssemblySyntaxHighlighter(QSyntaxHighlighter):
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
        self._rules: list[HighlightRule] = []
        self._setup_rules()

    @staticmethod
    def _create_format(
        color: str,
        *,
        bold: bool = False,
        italic: bool = False,
    ) -> QTextCharFormat:
        """Create a text format with specified style.

        Args:
            color: Hex color string.
            bold: Whether to use bold font.
            italic: Whether to use italic font.

        Returns:
            QTextCharFormat: Configured text format.
        """
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))
        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)
        return text_format

    def _setup_rules(self) -> None:
        """Set up assembly highlighting rules."""
        instr_format = AssemblySyntaxHighlighter._create_format("#569CD6", bold=True)
        for instr in self.INSTRUCTIONS:
            pattern = rf"\b{instr}\b"
            self._rules.append(HighlightRule(pattern, instr_format))

        reg_format = AssemblySyntaxHighlighter._create_format("#9CDCFE")
        for reg in self.REGISTERS:
            pattern = rf"\b{reg}\b"
            self._rules.append(HighlightRule(pattern, reg_format))

        mem_format = AssemblySyntaxHighlighter._create_format("#4EC9B0")
        for mem_kw in self.MEMORY_KEYWORDS:
            pattern = rf"\b{mem_kw}\b"
            self._rules.append(HighlightRule(pattern, mem_format))

        directive_format = AssemblySyntaxHighlighter._create_format("#C586C0")
        self._rules.append(HighlightRule(r"^\s*\.(text|data|bss|section|globl?|extern)\b", directive_format))
        self._rules.append(HighlightRule(r"\b(db|dw|dd|dq|resb|resw|resd|resq)\b", directive_format))

        addr_format = AssemblySyntaxHighlighter._create_format("#B5CEA8")
        self._rules.append(HighlightRule(r"\b0x[0-9A-Fa-f]+\b", addr_format))
        self._rules.append(HighlightRule(r"\b[0-9A-Fa-f]+h\b", addr_format))

        number_format = AssemblySyntaxHighlighter._create_format("#B5CEA8")
        self._rules.append(HighlightRule(r"\b\d+\b", number_format))

        label_format = AssemblySyntaxHighlighter._create_format("#DCDCAA")
        self._rules.append(HighlightRule(r"^[A-Za-z_][A-Za-z0-9_]*:", label_format))

        comment_format = AssemblySyntaxHighlighter._create_format("#6A9955", italic=True)
        self._rules.append(HighlightRule(r";.*$", comment_format))

        string_format = AssemblySyntaxHighlighter._create_format("#CE9178")
        self._rules.append(HighlightRule(r'"[^"]*"', string_format))
        self._rules.append(HighlightRule(r"'[^']*'", string_format))

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        for rule in self._rules:
            iterator = rule.pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    rule.format,
                )


class PythonSyntaxHighlighter(QSyntaxHighlighter):
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
        self._rules: list[HighlightRule] = []
        self._triple_quote_format = QTextCharFormat()
        self._setup_rules()

    @staticmethod
    def _create_format(
        color: str,
        *,
        bold: bool = False,
        italic: bool = False,
    ) -> QTextCharFormat:
        """Create a text format with specified style.

        Args:
            color: Hex color string.
            bold: Whether to use bold font.
            italic: Whether to use italic font.

        Returns:
            QTextCharFormat: Configured text format.
        """
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))
        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)
        return text_format

    def _setup_rules(self) -> None:
        """Set up Python highlighting rules."""
        keyword_format = PythonSyntaxHighlighter._create_format("#569CD6", bold=True)
        for keyword in self.KEYWORDS:
            pattern = rf"\b{keyword}\b"
            self._rules.append(HighlightRule(pattern, keyword_format))

        builtin_format = PythonSyntaxHighlighter._create_format("#4EC9B0")
        for builtin in self.BUILTINS:
            pattern = rf"\b{builtin}\b"
            self._rules.append(HighlightRule(pattern, builtin_format))

        function_format = PythonSyntaxHighlighter._create_format("#DCDCAA")
        self._rules.append(HighlightRule(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)", function_format))
        self._rules.append(HighlightRule(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", function_format))

        string_format = PythonSyntaxHighlighter._create_format("#CE9178")
        self._rules.append(HighlightRule(r'"[^"\\]*(\\.[^"\\]*)*"', string_format))
        self._rules.append(HighlightRule(r"'[^'\\]*(\\.[^'\\]*)*'", string_format))
        self._triple_quote_format = string_format

        number_format = PythonSyntaxHighlighter._create_format("#B5CEA8")
        self._rules.append(HighlightRule(r"\b0x[0-9A-Fa-f]+\b", number_format))
        self._rules.append(HighlightRule(r"\b0b[01]+\b", number_format))
        self._rules.append(HighlightRule(r"\b0o[0-7]+\b", number_format))
        self._rules.append(HighlightRule(r"\b\d+\.?\d*\b", number_format))

        comment_format = PythonSyntaxHighlighter._create_format("#6A9955", italic=True)
        self._rules.append(HighlightRule(r"#[^\n]*", comment_format))

        decorator_format = PythonSyntaxHighlighter._create_format("#C586C0")
        self._rules.append(HighlightRule(r"@[A-Za-z_][A-Za-z0-9_]*", decorator_format))

        self_format = PythonSyntaxHighlighter._create_format("#9CDCFE")
        self._rules.append(HighlightRule(r"\bself\b", self_format))
        self._rules.append(HighlightRule(r"\bcls\b", self_format))

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        for rule in self._rules:
            iterator = rule.pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    rule.format,
                )

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


class JavaScriptSyntaxHighlighter(QSyntaxHighlighter):
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
        self._rules: list[HighlightRule] = []
        self._multi_line_comment_format = QTextCharFormat()
        self._comment_start = QRegularExpression(r"/\*")
        self._comment_end = QRegularExpression(r"\*/")
        self._setup_rules()

    @staticmethod
    def _create_format(
        color: str,
        *,
        bold: bool = False,
        italic: bool = False,
    ) -> QTextCharFormat:
        """Create a text format with specified style.

        Args:
            color: Hex color string.
            bold: Whether to use bold font.
            italic: Whether to use italic font.

        Returns:
            QTextCharFormat: Configured text format.
        """
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))
        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)
        return text_format

    def _setup_rules(self) -> None:
        """Set up JavaScript highlighting rules."""
        keyword_format = JavaScriptSyntaxHighlighter._create_format("#569CD6", bold=True)
        for keyword in self.KEYWORDS:
            pattern = rf"\b{keyword}\b"
            self._rules.append(HighlightRule(pattern, keyword_format))

        frida_format = JavaScriptSyntaxHighlighter._create_format("#4EC9B0", bold=True)
        for frida_global in self.FRIDA_GLOBALS:
            pattern = rf"\b{frida_global}\b"
            self._rules.append(HighlightRule(pattern, frida_format))

        function_format = JavaScriptSyntaxHighlighter._create_format("#DCDCAA")
        self._rules.append(HighlightRule(r"\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()", function_format))

        string_format = JavaScriptSyntaxHighlighter._create_format("#CE9178")
        self._rules.append(HighlightRule(r'"[^"\\]*(\\.[^"\\]*)*"', string_format))
        self._rules.append(HighlightRule(r"'[^'\\]*(\\.[^'\\]*)*'", string_format))
        self._rules.append(HighlightRule(r"`[^`\\]*(\\.[^`\\]*)*`", string_format))

        number_format = JavaScriptSyntaxHighlighter._create_format("#B5CEA8")
        self._rules.append(HighlightRule(r"\b0x[0-9A-Fa-f]+\b", number_format))
        self._rules.append(HighlightRule(r"\b\d+\.?\d*\b", number_format))

        comment_format = JavaScriptSyntaxHighlighter._create_format("#6A9955", italic=True)
        self._rules.append(HighlightRule(r"//[^\n]*", comment_format))
        self._multi_line_comment_format = comment_format

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        for rule in self._rules:
            iterator = rule.pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    rule.format,
                )

        self.setCurrentBlockState(0)

        start_index = 0
        if self.previousBlockState() != 1:
            match = self._comment_start.match(text)
            start_index = match.capturedStart() if match.hasMatch() else -1

        while start_index >= 0:
            end_match = self._comment_end.match(text, start_index)
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                comment_length = end_index - start_index
                self.setCurrentBlockState(0)
            else:
                self.setCurrentBlockState(1)
                comment_length = len(text) - start_index

            self.setFormat(
                start_index,
                comment_length,
                self._multi_line_comment_format,
            )

            next_match = self._comment_start.match(text, start_index + comment_length)
            start_index = next_match.capturedStart() if next_match.hasMatch() else -1


class HexPatSyntaxHighlighter(QSyntaxHighlighter):
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
        self._rules: list[HighlightRule] = []
        self._multi_line_comment_format = QTextCharFormat()
        self._comment_start = QRegularExpression(r"/\*")
        self._comment_end = QRegularExpression(r"\*/")
        self._setup_rules()

    @staticmethod
    def _create_format(
        color: str,
        *,
        bold: bool = False,
        italic: bool = False,
    ) -> QTextCharFormat:
        """Create a text format with specified style.

        Args:
            color: Hex color string.
            bold: Whether to use bold font.
            italic: Whether to use italic font.

        Returns:
            QTextCharFormat: Configured text format.
        """
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))
        if bold:
            text_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            text_format.setFontItalic(True)
        return text_format

    def _setup_rules(self) -> None:
        """Set up HexPat highlighting rules."""
        keyword_format = HexPatSyntaxHighlighter._create_format("#569CD6", bold=True)
        for keyword in self.KEYWORDS:
            pattern = rf"\b{keyword}\b"
            self._rules.append(HighlightRule(pattern, keyword_format))

        type_format = HexPatSyntaxHighlighter._create_format("#4EC9B0")
        for type_name in self.TYPES:
            pattern = rf"\b{type_name}\b"
            self._rules.append(HighlightRule(pattern, type_format))

        endian_format = HexPatSyntaxHighlighter._create_format("#C586C0")
        for endian_kw in self.ENDIANNESS:
            pattern = rf"\b{endian_kw}\b"
            self._rules.append(HighlightRule(pattern, endian_format))

        builtin_format = HexPatSyntaxHighlighter._create_format("#DCDCAA")
        for builtin_name in self.BUILTINS:
            pattern = rf"\b{builtin_name}\b"
            self._rules.append(HighlightRule(pattern, builtin_format))
        self._rules.append(HighlightRule(r"\$", builtin_format))

        annotation_format = HexPatSyntaxHighlighter._create_format("#D7BA7D")
        self._rules.append(HighlightRule(r"\[\[.*?\]\]", annotation_format))

        attr_keyword_format = HexPatSyntaxHighlighter._create_format("#9CDCFE")
        for attr_kw in ("color", "validate", "description", "min", "max"):
            pattern = rf"\b{attr_kw}\b"
            self._rules.append(HighlightRule(pattern, attr_keyword_format))

        string_format = HexPatSyntaxHighlighter._create_format("#CE9178")
        self._rules.append(HighlightRule(r'"[^"\\]*(\\.[^"\\]*)*"', string_format))

        number_format = HexPatSyntaxHighlighter._create_format("#B5CEA8")
        self._rules.append(HighlightRule(r"\b0x[0-9A-Fa-f]+\b", number_format))
        self._rules.append(HighlightRule(r"\b\d+\b", number_format))

        comment_format = HexPatSyntaxHighlighter._create_format("#6A9955", italic=True)
        self._rules.append(HighlightRule(r"//[^\n]*", comment_format))
        self._multi_line_comment_format = comment_format

        operator_format = HexPatSyntaxHighlighter._create_format("#D4D4D4")
        self._rules.append(HighlightRule(r"[+\-*/%&|^~<>=!]+", operator_format))

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting to a block of text.

        Args:
            text: The text block to highlight.
        """
        if text is None:
            return
        for rule in self._rules:
            iterator = rule.pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    rule.format,
                )

        self.setCurrentBlockState(0)

        start_index = 0
        if self.previousBlockState() != 1:
            match = self._comment_start.match(text)
            start_index = match.capturedStart() if match.hasMatch() else -1

        while start_index >= 0:
            end_match = self._comment_end.match(text, start_index)
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                comment_length = end_index - start_index
                self.setCurrentBlockState(0)
            else:
                self.setCurrentBlockState(1)
                comment_length = len(text) - start_index

            self.setFormat(
                start_index,
                comment_length,
                self._multi_line_comment_format,
            )

            next_match = self._comment_start.match(text, start_index + comment_length)
            start_index = next_match.capturedStart() if next_match.hasMatch() else -1


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
