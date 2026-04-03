# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Top-level orchestrator for the .hexpat pattern language interpreter.

Chains preprocessor -> lexer -> parser -> evaluator into a single execute() call.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from intellicrack.core.hexpat._pragma import PragmaInfo
from intellicrack.core.hexpat.ast_nodes import ForStmt, FunctionDecl, MatchStmt, WhileStmt
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatError
from intellicrack.core.hexpat.evaluator import HexPatEvaluator
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions
from intellicrack.core.hexpat.type_system import TypeRegistry
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from typing import Any

    from intellicrack.core.types import HexDocumentLike


_logger = get_logger("core.hexpat.interpreter")

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_VENDOR_DIR = _PROJECT_ROOT / "vendor"
_IMHEX_PATTERNS_DIR = _VENDOR_DIR / "ImHex-Patterns"
_STD_LIB_DIR = _IMHEX_PATTERNS_DIR / "includes"
_PATTERNS_DIR = _IMHEX_PATTERNS_DIR / "patterns"


class HexPatInterpreter:
    """Full .hexpat pattern interpreter.

    Orchestrates the complete pipeline: preprocessor -> lexer -> parser ->
    type registration -> evaluator. Outputs ParsedField-compatible dicts
    that plug directly into the existing hex editor UI.

    Args:
        include_paths: Additional directories for ``#include`` resolution.
            The interpreter always searches the standard library directory
            (containing std/ and type/ libraries) first.
        std_lib_path: Override path for the standard library directory.
    """

    def __init__(
        self,
        include_paths: list[Path] | None = None,
        std_lib_path: Path | None = None,
    ) -> None:
        paths: list[Path] = []

        lib_path = std_lib_path if std_lib_path is not None else _STD_LIB_DIR
        if lib_path.exists():
            paths.append(lib_path)

        if include_paths:
            paths.extend(include_paths)

        self._include_paths: list[Path] = paths

    def execute(
        self,
        source: str,
        document: HexDocumentLike,
        offset: int = 0,
        file_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a .hexpat pattern against binary data.

        Args:
            source: The .hexpat source code to interpret.
            document: A HexDocument PyO3 object or any object with
                read(offset, length) -> list[int] and length() -> int.
            offset: Base offset in the binary data to start parsing.
            file_path: Path to the source file for #include resolution
                and error messages.

        Returns:
            list[dict[str, Any]]: A list of ParsedField-compatible dicts with keys: name, offset,
            size, raw_bytes, display_value, children, color,
            validation_passed, description.
        """
        preprocessor = HexPatPreprocessor(self._include_paths)
        file_str = str(file_path) if file_path else "<input>"

        processed_source, pragma = preprocessor.process(source, file_path)

        lexer = HexPatLexer(processed_source, file_str)
        tokens = lexer.tokenize()

        parser = HexPatParser(tokens, file_str)
        program = parser.parse()

        data_reader = DataReader.from_document(document)

        type_registry = TypeRegistry()

        if offset > 0:
            pragma = PragmaInfo(
                endian=pragma.endian,
                mime=pragma.mime,
                magic=pragma.magic,
                base_address=offset,
                eval_depth=pragma.eval_depth,
                array_limit=pragma.array_limit,
                pattern_limit=pragma.pattern_limit,
                author=pragma.author,
                description=pragma.description,
            )

        evaluator = HexPatEvaluator(data_reader, type_registry, pragma)

        stdlib = BuiltinFunctions(data_reader)
        stdlib.register_all(evaluator.scope)

        return evaluator.evaluate(program)

    def execute_file(
        self,
        pattern_path: Path,
        document: HexDocumentLike,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Execute a .hexpat file against binary data.

        Args:
            pattern_path: Path to the .hexpat file to execute.
            document: A HexDocument PyO3 object.
            offset: Base offset in the binary data.

        Returns:
            list[dict[str, Any]]: A list of ParsedField-compatible dicts.
        """
        source = pattern_path.read_text(encoding="utf-8", errors="replace")
        return self.execute(source, document, offset, pattern_path)

    def execute_bytes(
        self,
        source: str,
        data: bytes,
        offset: int = 0,
        file_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a .hexpat pattern against raw bytes.

        Convenience method for testing without a HexDocument.

        Args:
            source: The .hexpat source code.
            data: Raw binary data to parse.
            offset: Base offset in the data.
            file_path: Optional source file path.

        Returns:
            list[dict[str, Any]]: A list of ParsedField-compatible dicts.
        """
        preprocessor = HexPatPreprocessor(self._include_paths)
        file_str = str(file_path) if file_path else "<input>"

        processed_source, pragma = preprocessor.process(source, file_path)

        lexer = HexPatLexer(processed_source, file_str)
        tokens = lexer.tokenize()

        parser = HexPatParser(tokens, file_str)
        program = parser.parse()

        data_reader = DataReader.from_bytes(data)
        type_registry = TypeRegistry()

        if offset > 0:
            pragma = PragmaInfo(
                endian=pragma.endian,
                mime=pragma.mime,
                magic=pragma.magic,
                base_address=offset,
                eval_depth=pragma.eval_depth,
                array_limit=pragma.array_limit,
                pattern_limit=pragma.pattern_limit,
                author=pragma.author,
                description=pragma.description,
            )

        evaluator = HexPatEvaluator(data_reader, type_registry, pragma)

        stdlib = BuiltinFunctions(data_reader)
        stdlib.register_all(evaluator.scope)

        return evaluator.evaluate(program)

    def can_compile_to_json(self, source: str) -> bool:
        """Check if a pattern can be compiled to JSON for the fast Rust path.

        A pattern is eligible for JSON compilation if it contains only
        static struct/union/enum/bitfield declarations with no functions,
        loops, match statements, or runtime-computed expressions.

        Args:
            source: The .hexpat source code to check.

        Returns:
            bool: True if the pattern can be compiled to JSON.
        """
        try:
            preprocessor = HexPatPreprocessor(self._include_paths)
            processed_source, _pragma = preprocessor.process(source)
            lexer = HexPatLexer(processed_source)
            tokens = lexer.tokenize()
            parser = HexPatParser(tokens)
            program = parser.parse()
        except HexPatError:
            return False
        else:
            return not any(isinstance(node, (FunctionDecl, WhileStmt, ForStmt, MatchStmt)) for node in program)

    @staticmethod
    def compile_to_json(source: str) -> str:
        """Compile a simple pattern to JSON for the Rust evaluator.

        Delegates to the existing HexPatCompiler for patterns that pass
        can_compile_to_json().

        Args:
            source: The .hexpat source code.

        Returns:
            str: JSON string representing the template.

        Raises:
            HexPatError: If compilation fails.
        """
        try:
            from intellicrack.core.hexpat_compiler import HexPatCompiler

            result = HexPatCompiler.compile(source)
        except (HexPatError, ImportError) as exc:
            msg = str(exc)
            raise HexPatError(msg) from exc
        else:
            return result
