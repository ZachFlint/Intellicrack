# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Runtime-derived catalogue of every callable exposed by ``intellicrack_hexcore``.

The catalogue is built by combining two independent sources of truth: live
introspection of the compiled extension module, which supplies the authoritative
set of callables together with their parameter names and their static-versus-
instance binding, and the ``__init__.pyi`` stub shipped beside the ``.pyd``,
which supplies parameter and return type annotations that PyO3 does not expose
at runtime.

Deriving the catalogue rather than transcribing it means a method added to the
Rust crate appears in the GUI as soon as the extension is rebuilt, and any drift
between the compiled module and its stub is reported as an error instead of
silently narrowing what the harness can reach.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Final

import intellicrack_hexcore


__all__ = [
    "CatalogError",
    "Operation",
    "Parameter",
    "Receiver",
    "ValueKind",
    "build_catalog",
    "operation_names",
    "runtime_surface",
]

_DOCUMENT_TYPE: Final = "HexDocument"
_BOOKMARK_TYPE: Final = "Bookmark"
_STUB_NAME: Final = "__init__.pyi"


class CatalogError(RuntimeError):
    """Raised when the compiled module and its type stub disagree."""


class Receiver(Enum):
    """How an operation is invoked relative to a document instance."""

    DOCUMENT = "document"
    """Instance method, called on an open document."""

    FACTORY = "factory"
    """Static method that constructs and returns a new document."""

    STATIC = "static"
    """Static method that needs no document and returns plain data."""

    MODULE = "module"
    """Module-level function."""


class ValueKind(Enum):
    """Editing affordance the GUI should render for a parameter."""

    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    TEXT = "text"
    BYTES = "bytes"
    INT_PAIR = "int_pair"
    BOOL_PAIR = "bool_pair"
    BYTES_MAP = "bytes_map"
    BOOKMARK = "bookmark"


_ANNOTATION_KINDS: Final[dict[str, ValueKind]] = {
    "int": ValueKind.INT,
    "float": ValueKind.FLOAT,
    "bool": ValueKind.BOOL,
    "str": ValueKind.TEXT,
    "bytes": ValueKind.BYTES,
    "tuple[int, int]": ValueKind.INT_PAIR,
    "tuple[bool, bool]": ValueKind.BOOL_PAIR,
    "dict[str, bytes]": ValueKind.BYTES_MAP,
    _BOOKMARK_TYPE: ValueKind.BOOKMARK,
}

_GROUP_RULES: Final[tuple[tuple[str, str], ...]] = (
    ("search_", "Search"),
    ("replace_", "Search"),
    ("export_patches_", "Patches"),
    ("import_patches_", "Patches"),
    ("get_patches", "Patches"),
    ("compute_hash", "Hashing"),
    ("entropy", "Analysis"),
    ("byte_", "Analysis"),
    ("digram_", "Analysis"),
    ("content_classification", "Analysis"),
    ("extract_strings", "Analysis"),
    ("verify_pe_", "Analysis"),
    ("repair_pe_", "Analysis"),
    ("diff_", "Analysis"),
    ("_bookmark", "Bookmarks"),
    ("_template", "Templates"),
    ("apply_template", "Templates"),
    ("list_templates", "Templates"),
    ("_va_mapping", "Addressing"),
    ("file_offset_to_va", "Addressing"),
    ("va_to_file_offset", "Addressing"),
    ("_bit", "Bit editing"),
    ("fill_block", "Block editing"),
    ("copy_block", "Block editing"),
    ("move_block", "Block editing"),
    ("swap_blocks", "Block editing"),
    ("transform_data", "Transforms"),
    ("list_transforms", "Transforms"),
    ("decode_text", "Encodings"),
    ("encode_text_", "Encodings"),
    ("list_encodings", "Encodings"),
    ("_process_memory", "Process memory"),
    ("undo", "History"),
    ("redo", "History"),
    ("can_undo", "History"),
    ("can_redo", "History"),
    ("_chunk_size_hint", "Tuning"),
    ("_memory_budget_hint", "Tuning"),
    ("get_document_memory_usage", "Tuning"),
    ("inspect_at", "Inspector"),
)

_DEFAULT_GROUP: Final = "Document"


@dataclass(frozen=True, slots=True)
class Parameter:
    """One argument of a catalogued operation.

    Attributes:
        name: Parameter name as reported by runtime introspection.
        annotation: Source-level annotation text taken from the type stub.
        kind: Editing affordance the GUI renders for this parameter.
    """

    name: str
    annotation: str
    kind: ValueKind


@dataclass(frozen=True, slots=True)
class Operation:
    """A single callable exposed by the extension module.

    Attributes:
        name: Attribute name on its owner.
        receiver: How the operation is bound and invoked.
        parameters: Ordered arguments, excluding any ``self``.
        returns: Source-level return annotation from the type stub.
        group: Section label used to organise the GUI.
        mutating: Whether invoking it can alter document contents or state.
    """

    name: str
    receiver: Receiver
    parameters: tuple[Parameter, ...]
    returns: str
    group: str
    mutating: bool


_MUTATING_NAMES: Final[frozenset[str]] = frozenset({
    "write_bytes",
    "insert_bytes",
    "delete_bytes",
    "replace_bytes",
    "fill_block",
    "copy_block",
    "move_block",
    "swap_blocks",
    "set_bit",
    "toggle_bit",
    "undo",
    "redo",
    "save",
    "save_as",
    "add_bookmark",
    "add_bookmark_object",
    "update_bookmark",
    "remove_bookmark",
    "add_va_mapping",
    "remove_va_mapping",
    "register_json_template",
    "remove_template",
    "import_patches_ips",
    "import_patches_bps",
    "import_patches_ups",
    "repair_pe_checksum",
    "set_chunk_size_hint",
    "set_memory_budget_hint",
})


def _stub_path() -> Path:
    """Locate the type stub shipped beside the compiled extension.

    Returns:
        Path: Absolute path to the ``__init__.pyi`` stub.

    Raises:
        CatalogError: If the module has no resolvable file or the stub is absent.
    """
    module_file = getattr(intellicrack_hexcore, "__file__", None)
    if module_file is None:
        message = "intellicrack_hexcore does not expose __file__; cannot locate its type stub"
        raise CatalogError(message)
    stub = Path(module_file).with_name(_STUB_NAME)
    if not stub.is_file():
        message = f"type stub not found beside the extension module: {stub}"
        raise CatalogError(message)
    return stub


def _annotation_text(node: ast.expr | None) -> str:
    """Render an annotation node back to normalised source text.

    Args:
        node: Annotation expression, or ``None`` when unannotated.

    Returns:
        str: Normalised annotation text, or an empty string when unannotated.
    """
    if node is None:
        return ""
    return ast.unparse(node)


def _classify(annotation: str) -> ValueKind:
    """Map a stub annotation onto the GUI affordance used to edit it.

    Args:
        annotation: Normalised annotation text.

    Returns:
        ValueKind: Matching value kind.

    Raises:
        CatalogError: If the annotation has no registered affordance.
    """
    kind = _ANNOTATION_KINDS.get(annotation)
    if kind is None:
        message = (
            f"parameter annotation {annotation!r} has no editing affordance; "
            f"add it to _ANNOTATION_KINDS when the Rust API grows a new argument type"
        )
        raise CatalogError(message)
    return kind


def _group_for(name: str) -> str:
    """Choose the GUI section label for an operation.

    Args:
        name: Operation name.

    Returns:
        str: Section label, falling back to the general document group.
    """
    for fragment, group in _GROUP_RULES:
        if name.startswith(fragment) or (fragment.startswith("_") and name.endswith(fragment[1:])):
            return group
        if fragment.startswith("_") and fragment[1:] in name:
            return group
    return _DEFAULT_GROUP


def _stub_signatures() -> dict[str, tuple[list[tuple[str, str]], str]]:
    """Parse the type stub into per-operation parameter and return annotations.

    Returns:
        dict[str, tuple[list[tuple[str, str]], str]]: Mapping of operation name
        to its ordered ``(name, annotation)`` parameter pairs and its return
        annotation. Document methods and module functions share one namespace,
        since the two do not collide.

    Raises:
        CatalogError: If the stub cannot be parsed.
    """
    stub = _stub_path()
    try:
        tree = ast.parse(stub.read_text(encoding="utf-8"), filename=str(stub))
    except (OSError, SyntaxError) as exc:
        message = f"failed to parse type stub {stub}: {exc}"
        raise CatalogError(message) from exc

    signatures: dict[str, tuple[list[tuple[str, str]], str]] = {}

    def record(func: ast.FunctionDef) -> None:
        params: list[tuple[str, str]] = []
        for arg in func.args.args:
            if arg.arg == "self":
                continue
            params.append((arg.arg, _annotation_text(arg.annotation)))
        signatures[func.name] = (params, _annotation_text(func.returns))

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in {_DOCUMENT_TYPE, _BOOKMARK_TYPE}:
            for member in node.body:
                if isinstance(member, ast.FunctionDef):
                    record(member)
        elif isinstance(node, ast.FunctionDef):
            record(node)

    return signatures


def runtime_surface() -> tuple[frozenset[str], frozenset[str]]:
    """Enumerate the live public API of the compiled extension module.

    Returns:
        tuple[frozenset[str], frozenset[str]]: The public method names on
        ``HexDocument`` and the public module-level function names.
    """
    document_names = frozenset(name for name in dir(intellicrack_hexcore.HexDocument) if not name.startswith("_"))
    module_names = frozenset(
        name
        for name in dir(intellicrack_hexcore)
        if not name.startswith("_") and callable(getattr(intellicrack_hexcore, name)) and name[0].islower()
    )
    return document_names, module_names


def _receiver_for(name: str, returns: str) -> Receiver:
    """Determine how a document-owned operation is bound.

    Args:
        name: Method name on ``HexDocument``.
        returns: Return annotation from the type stub.

    Returns:
        Receiver: The binding classification for the method.
    """
    static = inspect.getattr_static(intellicrack_hexcore.HexDocument, name)
    if not isinstance(static, staticmethod):
        return Receiver.DOCUMENT
    if returns == _DOCUMENT_TYPE:
        return Receiver.FACTORY
    return Receiver.STATIC


def _build_operation(name: str, receiver: Receiver, signatures: dict[str, tuple[list[tuple[str, str]], str]]) -> Operation:
    """Assemble one catalogue entry from runtime and stub information.

    Args:
        name: Operation name.
        receiver: Binding classification.
        signatures: Parsed stub signatures keyed by operation name.

    Returns:
        Operation: The assembled operation.

    Raises:
        CatalogError: If the stub omits the operation or disagrees with the
            compiled module about its parameter names.
    """
    stub_entry = signatures.get(name)
    if stub_entry is None:
        message = f"{name!r} exists in the compiled module but is missing from the type stub"
        raise CatalogError(message)
    stub_params, returns = stub_entry

    owner = intellicrack_hexcore if receiver is Receiver.MODULE else intellicrack_hexcore.HexDocument
    live = inspect.signature(getattr(owner, name))
    live_names = [param for param in live.parameters if param != "self"]
    stub_names = [param for param, _ in stub_params]
    if live_names != stub_names:
        message = f"{name!r} parameter mismatch: compiled module has {live_names}, type stub has {stub_names}"
        raise CatalogError(message)

    parameters = tuple(Parameter(name=param, annotation=annotation, kind=_classify(annotation)) for param, annotation in stub_params)
    return Operation(
        name=name,
        receiver=receiver,
        parameters=parameters,
        returns=returns,
        group=_group_for(name),
        mutating=name in _MUTATING_NAMES,
    )


@lru_cache(maxsize=1)
def build_catalog() -> tuple[Operation, ...]:
    """Build the full operation catalogue for the loaded extension module.

    Propagates :class:`CatalogError` from the helpers it calls when the compiled
    module and its type stub disagree about which operations exist or what
    arguments they take.

    Returns:
        tuple[Operation, ...]: Every catalogued operation, ordered by group then
        name.

    Raises:
        CatalogError: If the type stub declares a callable the compiled module
            does not expose, or a helper reports any other drift between the
            compiled module and its stub.
    """
    signatures = _stub_signatures()
    document_names, module_names = runtime_surface()
    live_names = document_names | module_names

    stale = {name for name in signatures if not name.startswith("_")} - live_names
    if stale:
        message = (
            f"type stub declares {sorted(stale)} but the compiled module exposes no such callable; "
            "the Rust crate and its stub have drifted apart"
        )
        raise CatalogError(message)

    operations: list[Operation] = []
    for name in sorted(document_names):
        stub_entry = signatures.get(name)
        returns = stub_entry[1] if stub_entry is not None else ""
        operations.append(_build_operation(name, _receiver_for(name, returns), signatures))
    operations.extend(_build_operation(name, Receiver.MODULE, signatures) for name in sorted(module_names))

    operations.sort(key=lambda operation: (operation.group, operation.name))
    return tuple(operations)


def operation_names() -> frozenset[str]:
    """List the names of every catalogued operation.

    Returns:
        frozenset[str]: Frozen set of operation names.
    """
    return frozenset(operation.name for operation in build_catalog())
