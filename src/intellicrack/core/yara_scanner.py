# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""YARA rule scanning module for Intellicrack.

Provides synchronous and asynchronous YARA rule scanning against binary data and files, with version-transparent match object conversion.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.types import CompiledYaraRules


_logger = get_logger("core.yara_scanner")

_ERR_COMPILE_NA = "yara-python is not installed; cannot compile YARA rules"
_ERR_SCAN_NA = "yara-python is not installed; cannot scan"

_yara_mod: Any = None
_yara_available: bool = False
try:
    import yara as _yara_import

    _yara_mod = _yara_import
    _yara_available = True
except ImportError:
    pass


@dataclass(frozen=True, slots=True)
class YaraMatchString:
    """A single string match within a YARA rule match.

    Attributes:
        offset: Byte offset where the string was found.
        identifier: The string identifier from the YARA rule (e.g. ``$s0``).
        data: The raw bytes that matched.
    """

    offset: int
    identifier: str
    data: bytes


@dataclass(frozen=True, slots=True)
class YaraMatch:
    """A single YARA rule match result.

    Attributes:
        rule_name: Name of the matched YARA rule.
        tags: Tags attached to the rule.
        meta: Metadata dictionary from the rule definition.
        strings: List of string matches within this rule match.
        namespace: Namespace the rule belongs to.
    """

    rule_name: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[YaraMatchString]
    namespace: str = ""


class YaraScanner:
    """Thread-safe YARA rule scanner with async support.

    Compilation is not thread-safe; scanning compiled rules objects is.
    Use separate ``YaraScanner`` instances or external locking when compiling
    concurrently.

    Args:
        timeout: Maximum seconds allowed per match operation before
            a ``TimeoutError`` is raised by the YARA engine.
    """

    def __init__(self, timeout: int = 60) -> None:
        self._timeout = timeout
        if not _yara_available:
            _logger.warning("yara-python is not installed; YARA scanning unavailable")

    @property
    def available(self) -> bool:
        """Whether the yara-python library is importable.

        Returns:
            bool: ``True`` when yara-python was successfully imported, ``False``
            otherwise.
        """
        return _yara_available

    @staticmethod
    def compile_rules(paths: list[str | Path]) -> CompiledYaraRules:
        """Compile YARA rules from one or more rule files.

        Each file is compiled under a namespace derived from its stem so that
        rule names remain unambiguous across files.

        Args:
            paths: Filesystem paths to ``.yar`` / ``.yara`` rule files.

        Returns:
            CompiledYaraRules: A compiled YARA rules object whose ``match``
                method can be used for scanning.

        Raises:
            RuntimeError: When yara-python is not installed.
            ValueError: When compilation fails due to a syntax error in the
                rule source.
        """
        if not _yara_available or _yara_mod is None:
            raise RuntimeError(_ERR_COMPILE_NA)
        filepaths: dict[str, str] = {}
        for p in paths:
            resolved = Path(p).resolve()
            namespace = resolved.stem
            filepaths[namespace] = str(resolved)
        _logger.debug("compiling YARA rules", file_count=len(filepaths))
        try:
            compiled: CompiledYaraRules = _yara_mod.compile(filepaths=filepaths)
        except (ValueError, OSError, RuntimeError) as exc:
            msg = f"YARA compilation failed: {exc}"
            raise ValueError(msg) from exc
        else:
            return compiled

    @staticmethod
    def compile_source(source: str, namespace: str = "default") -> CompiledYaraRules:
        """Compile YARA rules from a source string.

        Args:
            source: Raw YARA rule source text.
            namespace: Namespace to assign to the compiled rules.

        Returns:
            CompiledYaraRules: A compiled YARA rules object.

        Raises:
            RuntimeError: When yara-python is not installed.
            ValueError: When compilation fails due to a syntax error.
        """
        if not _yara_available or _yara_mod is None:
            raise RuntimeError(_ERR_COMPILE_NA)
        _logger.debug("compiling YARA rules from source", namespace=namespace)
        sources: dict[str, str] = {namespace: source}
        try:
            compiled: CompiledYaraRules = _yara_mod.compile(sources=sources)
        except (ValueError, OSError, RuntimeError) as exc:
            msg = f"YARA compilation failed: {exc}"
            raise ValueError(msg) from exc
        else:
            return compiled

    def scan_data(self, data: bytes, rules: CompiledYaraRules) -> list[YaraMatch]:
        """Scan bytes in memory against compiled YARA rules.

        Args:
            data: The binary payload to scan.
            rules: A compiled YARA rules object returned by
                :meth:`compile_rules` or :meth:`compile_source`.

        Returns:
            list[YaraMatch]: A list of :class:`YaraMatch` instances, one per
                matching rule. Returns an empty list when no rules match.

        Raises:
            RuntimeError: When yara-python is not installed.
        """
        if not _yara_available:
            raise RuntimeError(_ERR_SCAN_NA)
        _logger.debug("scanning data buffer", buffer_size=len(data))
        raw_matches: list[object] = rules.match(data=data, timeout=self._timeout)
        return self._convert_matches(raw_matches)

    def scan_file(self, path: str | Path, rules: CompiledYaraRules) -> list[YaraMatch]:
        """Scan a file on disk against compiled YARA rules.

        Args:
            path: Path to the file to scan.
            rules: A compiled YARA rules object returned by
                :meth:`compile_rules` or :meth:`compile_source`.

        Returns:
            list[YaraMatch]: A list of :class:`YaraMatch` instances, one per
                matching rule. Returns an empty list when no rules match.

        Raises:
            RuntimeError: When yara-python is not installed.
        """
        if not _yara_available:
            raise RuntimeError(_ERR_SCAN_NA)
        resolved = str(Path(path).resolve())
        _logger.debug("scanning file", path=resolved)
        raw_matches: list[object] = rules.match(filepath=resolved, timeout=self._timeout)
        return self._convert_matches(raw_matches)

    async def scan_data_async(self, data: bytes, rules: CompiledYaraRules) -> list[YaraMatch]:
        """Asynchronously scan bytes in memory against compiled YARA rules.

        Delegates to :meth:`scan_data` via :func:`asyncio.to_thread` so that
        the event loop is not blocked during the scan.

        Args:
            data: The binary payload to scan.
            rules: A compiled YARA rules object.

        Returns:
            list[YaraMatch]:class:`YaraMatch` instances, one per matching rule.
        """
        return await asyncio.to_thread(self.scan_data, data, rules)

    async def scan_file_async(self, path: str | Path, rules: CompiledYaraRules) -> list[YaraMatch]:
        """Asynchronously scan a file on disk against compiled YARA rules.

        Delegates to :meth:`scan_file` via :func:`asyncio.to_thread` so that
        the event loop is not blocked during the scan.

        Args:
            path: Path to the file to scan.
            rules: A compiled YARA rules object.

        Returns:
            list[YaraMatch]:class:`YaraMatch` instances, one per matching rule.
        """
        return await asyncio.to_thread(self.scan_file, path, rules)

    @staticmethod
    def _convert_matches(raw_matches: list[Any]) -> list[YaraMatch]:
        """Convert raw yara-python match objects to :class:`YaraMatch` instances.

        Handles both the legacy tuple format ``(offset, identifier, data)``
        used in yara-python <4.x and the newer ``StringMatch`` /
        ``StringMatchInstance`` object format used in yara-python 4.x+.

        Args:
            raw_matches: List of raw match objects returned by
                ``rules.match()``.

        Returns:
            list[YaraMatch]:class:`YaraMatch` dataclass instances.
        """
        results: list[YaraMatch] = []
        for raw in raw_matches:
            rule_name: str = getattr(raw, "rule", "")
            tags: list[str] = list(getattr(raw, "tags", []))
            meta: dict[str, Any] = dict(getattr(raw, "meta", {}))
            namespace: str = getattr(raw, "namespace", "")
            strings: list[YaraMatchString] = []

            raw_strings: list[Any] = list(getattr(raw, "strings", []))
            for string_entry in raw_strings:
                if isinstance(string_entry, tuple):
                    se: tuple[Any, Any, Any] = cast("tuple[Any, Any, Any]", string_entry)
                    raw_offset: int = int(se[0])
                    raw_ident: str = str(se[1])
                    raw_data: bytes = bytes(se[2])
                    strings.append(
                        YaraMatchString(
                            offset=raw_offset,
                            identifier=raw_ident,
                            data=raw_data,
                        ),
                    )
                else:
                    identifier_val = str(getattr(string_entry, "identifier", ""))
                    instances: Any = getattr(string_entry, "instances", [])
                    for instance in instances:
                        offset_val = int(getattr(instance, "offset", 0))
                        data_val = bytes(getattr(instance, "matched_data", b""))
                        strings.append(
                            YaraMatchString(
                                offset=offset_val,
                                identifier=identifier_val,
                                data=data_val,
                            ),
                        )

            results.append(
                YaraMatch(
                    rule_name=rule_name,
                    tags=tags,
                    meta=meta,
                    strings=strings,
                    namespace=namespace,
                ),
            )
        return results
