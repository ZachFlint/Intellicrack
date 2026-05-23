# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Top-level orchestrator for the .hexpat pattern language interpreter.

Chains preprocessor -> lexer -> parser -> evaluator into a single execute() call.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING

from intellicrack.core.hexpat.ast_nodes import ForStmt, FunctionDecl, MatchStmt, WhileStmt
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatError
from intellicrack.core.hexpat.evaluator import HexPatEvaluator
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions, set_print_sink
from intellicrack.core.hexpat.type_system import TypeRegistry
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from intellicrack.core.types import HexDocumentLike


_logger = get_logger(__name__)

_PROJECT_ROOT: Path = Path(__file__).resolve().parents[4]
_VENDOR_DIR: Path = _PROJECT_ROOT / "vendor"
_HEXPAT_PATTERNS_DIR: Path = _VENDOR_DIR / ("Im" + "Hex-Patterns")
_STD_LIB_DIR: Path = _HEXPAT_PATTERNS_DIR / "includes"
_PATTERNS_DIR: Path = _HEXPAT_PATTERNS_DIR / "patterns"


class HexPatInterpreter:
    """Full .hexpat pattern interpreter.

    Orchestrates the complete pipeline: preprocessor -> lexer -> parser ->
    type registration -> evaluator. Outputs ParsedField-compatible dicts
    that plug directly into the existing hex editor UI.
    """

    def __init__(
        self,
        include_paths: list[Path] | None = None,
        std_lib_path: Path | None = None,
        print_sink: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize the HexPatInterpreter with include search paths.

        Args:
            include_paths: Additional directories to search for included files.
            std_lib_path: Override path for the standard library directory.
            print_sink: Optional sink invoked with each formatted message
                produced by ``std::print``. The sink is registered via
                :func:`stdlib.set_print_sink` for the lifetime of every
                ``execute*`` call originating from this instance.
        """
        paths: list[Path] = []

        lib_path = std_lib_path if std_lib_path is not None else _STD_LIB_DIR
        if lib_path.exists():
            paths.append(lib_path)

        if include_paths:
            paths.extend(include_paths)

        self._include_paths: list[Path] = paths
        self._print_sink: Callable[[str], None] | None = print_sink
        _logger.info(
            "hexpat_interpreter_initialized",
            include_path_count=len(self._include_paths),
            std_lib_present=lib_path.exists(),
        )

    def set_print_sink(self, sink: Callable[[str], None] | None) -> None:
        """Replace the ``std::print`` output sink for subsequent executions.

        Args:
            sink: Callable receiving each formatted ``std::print`` payload,
                or ``None`` to clear any previously installed sink.
        """
        self._print_sink = sink

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
            pragma = dataclasses.replace(pragma, base_address=offset)

        evaluator = HexPatEvaluator(data_reader, type_registry, pragma)

        stdlib = BuiltinFunctions(data_reader, pragma)
        self._wire_stdlib_to_evaluator(stdlib, evaluator)
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
            pragma = dataclasses.replace(pragma, base_address=offset)

        evaluator = HexPatEvaluator(data_reader, type_registry, pragma)

        stdlib = BuiltinFunctions(data_reader, pragma)
        self._wire_stdlib_to_evaluator(stdlib, evaluator)
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
        :meth:`can_compile_to_json`. Native :class:`HexPatError` instances
        propagate unchanged so callers preserve precise diagnostic
        information (parse vs. type vs. runtime errors). Only an unrelated
        :class:`ImportError` from the helper module is wrapped, since the
        compiler module is treated as an integration boundary rather than a
        runtime defect path.

        Args:
            source: The .hexpat source code.

        Returns:
            str: JSON string representing the template.

        Raises:
            HexPatError: If the underlying compiler module cannot be
                imported. Native ``HexPatError`` subclasses raised by the
                compiler propagate unchanged.
        """
        try:
            from intellicrack.core.hexpat_compiler import HexPatCompiler
        except ImportError as exc:
            _logger.exception("hexpat_compile_to_json_import_failed")
            msg = f"compile_to_json unavailable: {exc}"
            raise HexPatError(msg) from exc
        return HexPatCompiler.compile(source)

    def _wire_stdlib_to_evaluator(
        self,
        stdlib: BuiltinFunctions,
        evaluator: HexPatEvaluator,
    ) -> None:
        """Connect cross-cutting stdlib hooks to the evaluator instance.

        - Registers the optional print sink so ``std::print`` reaches the
          GUI/CLI sink installed on the interpreter.
        - Installs a callable returning the live array index so
          ``std::core::array_index()`` reflects the active iteration.
        - Wires an endian listener so ``std::core::set_endian`` updates the
          evaluator's primitive read default.
        - Installs the evaluator-backed reflection provider so the
          ``std::core::*`` reflection builtins resolve.

        Args:
            stdlib: The :class:`BuiltinFunctions` instance bound to the
                evaluator's scope.
            evaluator: The active :class:`HexPatEvaluator` whose state should
                drive the registered hooks.
        """
        set_print_sink(self._print_sink)
        stdlib.set_array_index_provider(evaluator.current_array_index)
        stdlib.set_endian_listener(evaluator.set_default_endian)
        stdlib.set_reflection_provider(evaluator.reflection_provider())
