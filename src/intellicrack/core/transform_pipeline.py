# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Transform pipeline system for chaining binary data transformations.

Provides a Python-side pipeline that wraps Rust hexcore transforms and exposes additional Python-only transform nodes. Pipelines can be
built from any combination of Rust-accelerated and pure-Python steps.
"""

from __future__ import annotations

import abc
import ast
import operator
import re
import string
from dataclasses import dataclass, field
from itertools import starmap
from typing import Any, override

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

_MAX_BYTE_VALUE = 255

_NODE_REGEX = "RegexReplaceNode"
_NODE_EXPR = "CustomExpressionNode"
_NODE_REPEAT = "RepeatNode"
_NODE_TRUNCATE = "TruncateNode"
_NODE_PAD = "PadNode"
_ERR_REQUIRES_PATTERN = "requires 'pattern'"
_ERR_REQUIRES_EXPRESSION = "requires 'expression'"
_ERR_REQUIRES_LENGTH = "requires 'length'"


class ExpressionError(ValueError):
    """Raised when a restricted AST expression uses unsupported constructs."""


class UnsupportedConstantTypeError(TypeError):
    """Raised when an AST constant has an unsupported type."""

    def __init__(self, type_name: str) -> None:
        """Initialize the UnsupportedConstantTypeError with the offending type name.

        Args:
            type_name: Name of the AST constant type that is unsupported.
        """
        super().__init__(f"Unsupported constant type: {type_name}")


class TransformParamError(ValueError):
    """Raised when a transform node receives invalid parameters."""

    def __init__(self, node_name: str, detail: str) -> None:
        """Initialize the TransformParamError with node name and detail.

        Args:
            node_name: Name of the transform node that produced the error.
            detail: Description of the invalid parameter or reason.
        """
        super().__init__(f"{node_name}: {detail}")


class HexcoreUnavailableError(RuntimeError):
    """Raised when intellicrack_hexcore is not importable."""


_hexcore_mod: Any = None
_hexcore_available: bool = False
try:
    import intellicrack_hexcore

    _hexcore_mod = intellicrack_hexcore
    _hexcore_available = True
except ImportError:
    _logger.debug("hexcore_module_import_failed")


_BINARY_OPS: dict[type[ast.operator], Any] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
}

_UNARY_OPS: dict[type[ast.unaryop], Any] = {
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Invert: operator.invert,
    ast.Not: operator.not_,
}

_COMPARE_OPS: dict[type[ast.cmpop], Any] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


def _eval_ast_node(node: ast.expr, b: int, i: int) -> int:
    """Evaluate a restricted AST expression node.

    Supports arithmetic, bitwise, comparison, and conditional expressions
    using ``b`` (byte value) and ``i`` (byte index) as variables. No
    attribute access, function calls, or imports are permitted.

    Args:
        node: AST expression node to evaluate.
        b: Current byte value (0-255).
        i: Current byte index.

    Returns:
        int: Result of the expression, as a Python integer.

    Raises:
        UnsupportedConstantTypeError: If a constant has an unsupported type.
        ExpressionError: If the expression uses unsupported constructs.
    """
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, (int, float, bool)):
            _logger.error(
                "ast_node_unsupported_constant",
                type_name=type(node.value).__name__,
            )
            raise UnsupportedConstantTypeError(type(node.value).__name__)
        return int(node.value)

    if isinstance(node, ast.Name):
        if node.id == "b":
            return b
        if node.id == "i":
            return i
        msg = f"Unknown variable: {node.id!r}"
        raise ExpressionError(msg)

    if isinstance(node, ast.BinOp):
        op_fn = _BINARY_OPS.get(type(node.op))
        if op_fn is None:
            msg = f"Unsupported binary op: {type(node.op).__name__}"
            raise ExpressionError(msg)
        left = _eval_ast_node(node.left, b, i)
        right = _eval_ast_node(node.right, b, i)
        return int(op_fn(left, right))

    if isinstance(node, ast.UnaryOp):
        op_fn = _UNARY_OPS.get(type(node.op))
        if op_fn is None:
            msg = f"Unsupported unary op: {type(node.op).__name__}"
            raise ExpressionError(msg)
        operand = _eval_ast_node(node.operand, b, i)
        return int(op_fn(operand))

    if isinstance(node, ast.Compare):
        left = _eval_ast_node(node.left, b, i)
        for cmp_op, comparator_node in zip(node.ops, node.comparators, strict=False):
            op_fn = _COMPARE_OPS.get(type(cmp_op))
            if op_fn is None:
                msg = f"Unsupported compare op: {type(cmp_op).__name__}"
                raise ExpressionError(msg)
            right = _eval_ast_node(comparator_node, b, i)
            if not op_fn(left, right):
                return 0
            left = right
        return 1

    if isinstance(node, ast.IfExp):
        if _eval_ast_node(node.test, b, i):
            return _eval_ast_node(node.body, b, i)
        return _eval_ast_node(node.orelse, b, i)

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            last = 1
            for value_node in node.values:
                last = _eval_ast_node(value_node, b, i)
                if not last:
                    return 0
            return last
        if isinstance(node.op, ast.Or):
            for value_node in node.values:
                if candidate := _eval_ast_node(value_node, b, i):
                    return candidate
            return 0

    msg = f"Unsupported node type: {type(node).__name__}"
    raise ExpressionError(msg)


class TransformNode(abc.ABC):
    """Abstract base class for a single transform step in a pipeline.

    Concrete subclasses must implement ``name``, ``category``, and ``process``. ``name`` identifies the transform, ``category`` groups it
    for UI presentation, and ``process`` performs the actual byte-level transformation. ``description`` has a default empty implementation
    and may be overridden to provide human-readable help text.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique identifier for this transform.

        Returns:
            str: Transform name.
        """

    @property
    @abc.abstractmethod
    def category(self) -> str:
        """Grouping category for this transform.

        Returns:
            str: Category string.
        """

    @property
    def description(self) -> str:
        """Human-readable description of what the transform does.

        Returns:
            str: Description string, empty by default.
        """
        return ""

    @abc.abstractmethod
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Apply this transform to binary data.

        Args:
            data: Input bytes to transform.
            params: Transform-specific parameters.

        Returns:
            bytes: Transformed output bytes.
        """


class RustTransformNode(TransformNode):
    """Wraps a Rust hexcore transform exposed via ``HexDocument.transform_data``."""

    def __init__(
        self,
        transform_name: str,
        transform_category: str = "",
        transform_description: str = "",
    ) -> None:
        """Initialize the RustTransformNode with transform metadata.

        Args:
            transform_name: Name of the Rust-side transform to invoke.
            transform_category: Category string for the transform.
            transform_description: Human-readable description.
        """
        self._name = transform_name
        self._category = transform_category
        self._description = transform_description

    @property
    def name(self) -> str:
        """Rust transform name.

        Returns:
            str: The registered transform name on the Rust side.
        """
        return self._name

    @property
    def category(self) -> str:
        """Transform category.

        Returns:
            str: Category string supplied at construction.
        """
        return self._category

    @property
    def description(self) -> str:
        """Transform description.

        Returns:
            str: Description string supplied at construction.
        """
        return self._description

    @override
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Apply the Rust-side transform to data.

        Creates a temporary ``HexDocument`` from ``data``, calls
        ``transform_data``, and returns the result. String params are
        interpreted as hex if they are valid even-length hex strings, or
        encoded as UTF-8 otherwise. Integer params are converted to
        little-endian bytes.

        Args:
            data: Input bytes to transform.
            params: Transform parameters whose values are coerced to bytes
                before being forwarded to the Rust layer.

        Returns:
            bytes: Transformed output bytes.

        Raises:
            HexcoreUnavailableError: If hexcore is not available.
        """
        if not _hexcore_available or _hexcore_mod is None:
            raise HexcoreUnavailableError

        doc = _hexcore_mod.HexDocument.open_bytes(data)

        rust_params: dict[str, bytes] = {}
        for key, val in params.items():
            if isinstance(val, bytes):
                rust_params[key] = val
            elif isinstance(val, int):
                if 0 <= val <= _MAX_BYTE_VALUE:
                    rust_params[key] = val.to_bytes(1, "little")
                else:
                    rust_params[key] = val.to_bytes(8, "little")
            elif isinstance(val, str):
                is_hex = len(val) > 0 and len(val) % 2 == 0 and all(c in string.hexdigits for c in val)
                rust_params[key] = bytes.fromhex(val) if is_hex else val.encode("utf-8")
            else:
                rust_params[key] = str(val).encode("utf-8")

        result: bytes = bytes(doc.transform_data(self._name, 0, len(data), rust_params))
        return result


class RegexReplaceNode(TransformNode):
    """Replace binary patterns in data using a regular expression.

    The regex is applied to the raw byte string. The replacement is
    specified as a hex string in ``params["replacement"]``.

    Params:
        pattern: Regex pattern string applied to raw bytes (required).
        replacement: Replacement bytes as a hex string (default: empty).
    """

    @property
    def name(self) -> str:
        """Node name.

        Returns:
            str: "regex_replace".
        """
        return "regex_replace"

    @property
    def category(self) -> str:
        """Node category.

        Returns:
            str: "python".
        """
        return "python"

    @property
    def description(self) -> str:
        """Node description.

        Returns:
            str: Human-readable description.
        """
        return "Replace binary patterns using a regular expression"

    @override
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Apply regex search-and-replace on binary data.

        Args:
            data: Input bytes.
            params: Must contain ``"pattern"`` (str). Optionally
                ``"replacement"`` (hex string, default empty bytes).

        Returns:
            bytes: Data with all pattern matches replaced.

        Raises:
            TransformParamError: If ``"pattern"`` is missing or invalid.
        """
        raw_pattern = params.get("pattern")
        if not isinstance(raw_pattern, str) or not raw_pattern:
            raise TransformParamError(_NODE_REGEX, _ERR_REQUIRES_PATTERN)

        raw_replacement = params.get("replacement", "")
        if isinstance(raw_replacement, bytes):
            replacement = raw_replacement
        elif isinstance(raw_replacement, str):
            replacement = bytes.fromhex(raw_replacement) if raw_replacement else b""
        else:
            replacement = str(raw_replacement).encode("utf-8")

        try:
            compiled = re.compile(raw_pattern.encode("latin-1"))
        except re.error as exc:
            detail = f"invalid regex: {exc}"
            raise TransformParamError(_NODE_REGEX, detail) from exc

        return compiled.sub(replacement, data)


class CustomExpressionNode(TransformNode):
    r"""Apply a Python expression to each byte individually.

    The expression is evaluated per byte with ``b`` bound to the current
    byte value (0-255) and ``i`` bound to the byte index. The result is
    masked to 8 bits with ``& 0xFF``.

    Params:
        expression: Python expression string, e.g. ``"b ^ 0x55"`` or
            ``"(b + i) & 0xFF"``.

    Example::

        node = CustomExpressionNode()
        result = node.process(b"\x00\x01\x02", {"expression": "b ^ 0x55"})
    """

    @property
    def name(self) -> str:
        """Node name.

        Returns:
            str: "custom_expression".
        """
        return "custom_expression"

    @property
    def category(self) -> str:
        """Node category.

        Returns:
            str: "python".
        """
        return "python"

    @property
    def description(self) -> str:
        """Node description.

        Returns:
            str: Human-readable description.
        """
        return "Apply a Python expression to each byte; use 'b' for byte value, 'i' for index"

    @override
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Evaluate the expression for every byte in data.

        The expression is parsed with ``ast.parse`` and evaluated using a
        restricted AST walker that supports only arithmetic, bitwise,
        comparison, and conditional operations on the variables ``b`` and
        ``i``. No ``eval`` or ``exec`` calls are made.

        Args:
            data: Input bytes.
            params: Must contain ``"expression"`` (str).

        Returns:
            bytes: Transformed bytes with each value masked to 0-255.

        Raises:
            TransformParamError: If ``"expression"`` is missing or
                syntactically invalid.
        """
        expression = params.get("expression")
        if not isinstance(expression, str) or not expression:
            raise TransformParamError(_NODE_EXPR, _ERR_REQUIRES_EXPRESSION)

        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as exc:
            detail = f"bad syntax: {exc}"
            raise TransformParamError(_NODE_EXPR, detail) from exc

        expr_node = tree.body
        result = bytearray(len(data))
        for idx, byte_val in enumerate(data):
            result[idx] = _eval_ast_node(expr_node, byte_val, idx) & 0xFF

        return bytes(result)


class RepeatNode(TransformNode):
    """Repeat the input data a specified number of times.

    Params:
        count: Number of repetitions (int, must be >= 1).
    """

    @property
    def name(self) -> str:
        """Node name.

        Returns:
            str: "repeat".
        """
        return "repeat"

    @property
    def category(self) -> str:
        """Node category.

        Returns:
            str: "python".
        """
        return "python"

    @property
    def description(self) -> str:
        """Node description.

        Returns:
            str: Human-readable description.
        """
        return "Repeat input data N times"

    @override
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Repeat data by the count factor.

        Args:
            data: Input bytes to repeat.
            params: Must contain ``"count"`` (int >= 1).

        Returns:
            bytes: Input bytes concatenated ``count`` times.

        Raises:
            TransformParamError: If ``"count"`` is missing or less than 1.
        """
        raw_count = params.get("count", 1)
        try:
            count = int(raw_count)
        except (TypeError, ValueError) as exc:
            detail = f"'count' not int: {raw_count!r}"
            raise TransformParamError(_NODE_REPEAT, detail) from exc

        if count < 1:
            detail = f"'count' must be >= 1, got {count}"
            raise TransformParamError(_NODE_REPEAT, detail)

        return data * count


class TruncateNode(TransformNode):
    """Truncate data to a maximum number of bytes.

    Params:
        length: Maximum number of bytes to keep (int, must be >= 0).
    """

    @property
    def name(self) -> str:
        """Node name.

        Returns:
            str: "truncate".
        """
        return "truncate"

    @property
    def category(self) -> str:
        """Node category.

        Returns:
            str: "python".
        """
        return "python"

    @property
    def description(self) -> str:
        """Node description.

        Returns:
            str: Human-readable description.
        """
        return "Truncate data to at most N bytes"

    @override
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Return the first ``length`` bytes of data.

        Args:
            data: Input bytes.
            params: Must contain ``"length"`` (int >= 0).

        Returns:
            bytes: First ``length`` bytes, or all of ``data`` if shorter.

        Raises:
            TransformParamError: If ``"length"`` is missing or negative.
        """
        raw_length = params.get("length")
        if raw_length is None:
            raise TransformParamError(_NODE_TRUNCATE, _ERR_REQUIRES_LENGTH)

        try:
            length = int(raw_length)
        except (TypeError, ValueError) as exc:
            detail = f"'length' not int: {raw_length!r}"
            raise TransformParamError(_NODE_TRUNCATE, detail) from exc

        if length < 0:
            detail = f"'length' must be >= 0, got {length}"
            raise TransformParamError(_NODE_TRUNCATE, detail)

        return data[:length]


class PadNode(TransformNode):
    """Pad data to a target length with a specified fill byte.

    If data is already at or beyond ``length``, it is returned unchanged.

    Params:
        length: Target length in bytes (int, must be >= 0).
        byte: Fill byte value 0-255 (int, default 0).
    """

    @property
    def name(self) -> str:
        """Node name.

        Returns:
            str: "pad".
        """
        return "pad"

    @property
    def category(self) -> str:
        """Node category.

        Returns:
            str: "python".
        """
        return "python"

    @property
    def description(self) -> str:
        """Node description.

        Returns:
            str: Human-readable description.
        """
        return "Pad data to a target length with a fill byte"

    @override
    def process(self, data: bytes, params: dict[str, Any]) -> bytes:
        """Pad data to the requested length.

        Args:
            data: Input bytes.
            params: Must contain ``"length"`` (int >= 0). Optionally
                ``"byte"`` (int 0-255, default 0).

        Returns:
            bytes: Data padded to ``length`` bytes, or unchanged if already
                long enough.

        Raises:
            TransformParamError: If ``"length"`` is missing, negative, or
                ``"byte"`` is outside 0-255.
        """
        raw_length = params.get("length")
        if raw_length is None:
            raise TransformParamError(_NODE_PAD, _ERR_REQUIRES_LENGTH)

        try:
            length = int(raw_length)
        except (TypeError, ValueError) as exc:
            detail = f"'length' not int: {raw_length!r}"
            raise TransformParamError(_NODE_PAD, detail) from exc

        if length < 0:
            detail = f"'length' must be >= 0, got {length}"
            raise TransformParamError(_NODE_PAD, detail)

        raw_byte = params.get("byte", 0)
        try:
            fill_byte = int(raw_byte)
        except (TypeError, ValueError) as exc:
            detail = f"'byte' not int: {raw_byte!r}"
            raise TransformParamError(_NODE_PAD, detail) from exc

        if not 0 <= fill_byte <= _MAX_BYTE_VALUE:
            detail = f"'byte' must be 0-255, got {fill_byte}"
            raise TransformParamError(_NODE_PAD, detail)

        if len(data) >= length:
            return data

        padding_needed = length - len(data)
        return data + bytes([fill_byte] * padding_needed)


@dataclass
class PipelineStep:
    """A single step in a transform pipeline.

    Attributes:
        node: The transform node to execute.
        params: Parameters to pass to the node's ``process`` method.
    """

    node: TransformNode
    params: dict[str, Any] = field(default_factory=dict)


class TransformPipeline:
    """Ordered chain of binary transform operations.

    Steps execute in insertion order, each receiving the output of the previous step as its input. The pipeline accumulates steps via
    ``add_step`` and executes them via ``execute`` or ``preview``.
    """

    def __init__(self) -> None:
        """Initialize the TransformPipeline instance."""
        self._steps: list[PipelineStep] = []

    def add_step(self, node: TransformNode, params: dict[str, Any] | None = None) -> int:
        """Append a transform step to the end of the pipeline.

        Args:
            node: Transform node to add.
            params: Optional parameters for the node. Defaults to an empty
                dict if not provided.

        Returns:
            int: Zero-based index of the newly added step.
        """
        step = PipelineStep(node=node, params=params if params is not None else {})
        self._steps.append(step)
        _logger.debug(
            "pipeline_step_added",
            node=node.name,
            index=len(self._steps) - 1,
        )
        return len(self._steps) - 1

    def remove_step(self, index: int) -> bool:
        """Remove the step at the given index.

        Args:
            index: Zero-based index of the step to remove.

        Returns:
            bool: True if the step was removed, False if the index was out of
                range.
        """
        if index < 0 or index >= len(self._steps):
            return False
        removed = self._steps.pop(index)
        _logger.info("pipeline_step_removed", node=removed.node.name, index=index)
        return True

    def move_step(self, from_index: int, to_index: int) -> bool:
        """Reorder a step within the pipeline.

        Args:
            from_index: Current zero-based index of the step.
            to_index: Target zero-based index after the move.

        Returns:
            bool: True if the move succeeded, False if either index was out
                of range.
        """
        n = len(self._steps)
        if from_index < 0 or from_index >= n or to_index < 0 or to_index >= n:
            return False
        step = self._steps.pop(from_index)
        self._steps.insert(to_index, step)
        _logger.debug(
            "pipeline_step_moved",
            node=step.node.name,
            from_index=from_index,
            to_index=to_index,
        )
        return True

    def execute(self, data: bytes) -> bytes:
        """Execute all pipeline steps in order on the input data.

        Each step receives the output of the previous step. Steps are
        executed even if ``data`` is empty.

        Args:
            data: Initial input bytes.

        Returns:
            bytes: Final output after all steps have been applied.
        """
        result = data
        for step in self._steps:
            result = step.node.process(result, step.params)
        return result

    def preview(self, data: bytes) -> list[tuple[str, bytes]]:
        """Execute the pipeline and capture intermediate outputs.

        Args:
            data: Initial input bytes.

        Returns:
            list[tuple[str, bytes]]: One entry per step containing the step
                name and the bytes produced by that step.
        """
        results: list[tuple[str, bytes]] = []
        current = data
        for step in self._steps:
            current = step.node.process(current, step.params)
            results.append((step.node.name, current))
        return results

    @property
    def steps(self) -> list[PipelineStep]:
        """Return a shallow copy of the current step list.

        Returns:
            list[PipelineStep]: Copy of all pipeline steps in order.
        """
        return list(self._steps)

    def clear(self) -> None:
        """Remove all steps from the pipeline."""
        self._steps.clear()
        _logger.info("pipeline_cleared")


def get_all_transform_nodes() -> list[TransformNode]:
    """Build a list of all available transform nodes.

    Rust hexcore transforms are included when the extension module is
    importable. Python-only transforms are always included.

    Returns:
        list[TransformNode]: All available transform nodes, Rust transforms
            first followed by Python-only transforms.
    """
    nodes: list[TransformNode] = []

    if _hexcore_available and _hexcore_mod is not None:
        doc = _hexcore_mod.HexDocument()
        nodes.extend(
            starmap(RustTransformNode, doc.list_transforms()),
        )
        _logger.debug("hexcore_transforms_loaded", count=len(nodes))

    python_nodes: list[TransformNode] = [
        RegexReplaceNode(),
        CustomExpressionNode(),
        RepeatNode(),
        TruncateNode(),
        PadNode(),
    ]
    nodes.extend(python_nodes)
    _logger.debug("all_transforms_loaded", total=len(nodes))
    return nodes
