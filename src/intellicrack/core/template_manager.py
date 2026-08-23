# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Template file management for the hex editor pattern system.

Manages template storage, loading, saving, and directory structure for both built-in and user-defined binary structure templates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from intellicrack.core.hexpat import PatternRegistry
    from intellicrack.core.types import HexDocumentFull


_logger = get_logger(__name__)

_PatternRegistry: type[Any] | None = None
_hexpat_registry_available: bool = False
try:
    from intellicrack.core.hexpat.pattern_registry import (
        PatternRegistry as _PatternRegistry,
    )

    _hexpat_registry_available = True
except (ImportError, OSError, AttributeError):
    _logger.debug("hexpat_registry_unavailable")


@dataclass(frozen=True)
class TemplateInfo:
    """Metadata about a template file.

    Attributes:
        name: Template name.
        description: Human-readable description.
        category: Category grouping (e.g. PE, ELF, Custom).
        is_builtin: Whether this is a built-in template.
        json_path: Path to the JSON template file.
        dsl_path: Path to the DSL source file, if available.
    """

    name: str
    description: str
    category: str
    is_builtin: bool
    json_path: Path
    dsl_path: Path | None


_BUILTIN_CATEGORIES: tuple[str, ...] = ("pe", "elf", "macho", "zip", "common")


class TemplateBootstrapError(RuntimeError):
    """Raised when built-in template bootstrap encounters failures.

    Aggregates per-template failures encountered while exporting built-in
    templates or parsing template files so callers can react to or report
    them without losing information.

    Attributes:
        failed_templates: Sequence of ``(path, error_message)`` pairs describing
            each failure encountered during bootstrap.
    """

    failed_templates: Sequence[tuple[Path, str]]

    def __init__(
        self,
        message: str,
        failed_templates: Sequence[tuple[Path, str]],
    ) -> None:
        """Initialize the error with a message and failure details.

        Args:
            message: Human-readable summary of the bootstrap failure.
            failed_templates: Sequence of ``(path, error_message)`` pairs for
                every template that failed to export or parse.
        """
        super().__init__(message)
        self.failed_templates = tuple(failed_templates)


class TemplateManager:
    """Manages template files on disk for the hex editor.

    Maintains a directory structure under config_dir/templates/ with builtin and user subdirectories.
    """

    def __init__(self, config_dir: Path) -> None:
        """Initialize the TemplateManager with a configuration directory.

        Args:
            config_dir: Base configuration directory.
        """
        self._config_dir = config_dir
        self._templates_dir = config_dir / "templates"
        self._builtin_dir = self._templates_dir / "builtin"
        self._user_dir = self._templates_dir / "user"
        self._pattern_registry: Any | None = None
        self.failed_templates: list[tuple[Path, str]] = []
        _logger.debug(
            "template_manager_initialized",
            config_dir=str(config_dir),
            templates_dir=str(self._templates_dir),
        )

    def ensure_directories(self) -> None:
        """Create the template directory structure if it doesn't exist."""
        self._templates_dir.mkdir(parents=True, exist_ok=True)
        for category in _BUILTIN_CATEGORIES:
            (self._builtin_dir / category).mkdir(parents=True, exist_ok=True)
        self._user_dir.mkdir(parents=True, exist_ok=True)
        _logger.debug("template_directories_ensured", path=str(self._templates_dir))

    def bootstrap_builtins(self, document: HexDocumentFull) -> None:
        """Export all built-in templates as JSON files.

        Skips export only when every expected built-in template already exists
        in the registry on disk. Otherwise iterates over the document's
        template list, exporting any missing entries via
        ``export_template_json`` and aggregating per-template failures.
        Failures are logged at ``warning`` and appended to
        ``self.failed_templates``; if any failures occurred a
        :class:`TemplateBootstrapError` is raised after all templates have
        been processed.

        Args:
            document: HexDocument instance exposing
                ``list_templates_detailed`` and ``export_template_json``.

        Raises:
            TemplateBootstrapError: If one or more built-in templates failed
                to export, or if the document is missing the required
                template methods while bootstrap is still required.
        """
        self.ensure_directories()
        self.failed_templates = []

        list_detailed_fn = getattr(document, "list_templates_detailed", None)
        export_fn = getattr(document, "export_template_json", None)

        existing_json_paths = list(self._builtin_dir.rglob("*.json"))
        existing_names = {path.stem for path in existing_json_paths}

        expected_names: set[str] = set()
        template_entries: list[tuple[str, str, str, int]] = []
        if callable(list_detailed_fn):
            raw_result: object = list_detailed_fn()
            if isinstance(raw_result, list):
                template_entries = cast("list[tuple[str, str, str, int]]", raw_result)
                expected_names = {entry[0] for entry in template_entries}

        if expected_names and expected_names.issubset(existing_names):
            _logger.debug(
                "builtin_templates_already_exist",
                count=len(existing_json_paths),
            )
            return

        if not callable(list_detailed_fn) or not callable(export_fn):
            message = "document is missing list_templates_detailed or export_template_json"
            _logger.warning("document_missing_template_methods")
            raise TemplateBootstrapError(message, self.failed_templates)

        if not template_entries:
            _logger.warning("unexpected_template_list_type")
            no_entries_message = "list_templates_detailed returned no usable entries"
            raise TemplateBootstrapError(no_entries_message, self.failed_templates)

        exported = sum(bool(self._bootstrap_single_template(tmpl_entry, export_fn)) for tmpl_entry in template_entries)
        _logger.info("builtin_templates_bootstrapped", count=exported)

        if self.failed_templates:
            message = f"bootstrap encountered {len(self.failed_templates)} template failure(s)"
            raise TemplateBootstrapError(message, self.failed_templates)

    def _bootstrap_single_template(
        self,
        tmpl_entry: tuple[str, str, str, int],
        export_fn: Callable[[str], object],
    ) -> bool:
        """Export a single built-in template to its JSON file.

        Args:
            tmpl_entry: Tuple of (name, description, category, field_count).
            export_fn: Document-provided export_template_json callable.

        Returns:
            bool: True on success; False if the template failed to export
                (with the failure appended to ``self.failed_templates``).
        """
        name = tmpl_entry[0]
        category = tmpl_entry[2]
        cat_lower = category.lower().replace("-", "") if category else "common"
        if cat_lower not in _BUILTIN_CATEGORIES:
            cat_lower = "common"

        cat_dir = self._builtin_dir / cat_lower
        cat_dir.mkdir(parents=True, exist_ok=True)
        target_path = cat_dir / f"{name}.json"

        try:
            raw_json: object = export_fn(name)
        except (OSError, ValueError, RuntimeError) as exc:
            _logger.warning("builtin_export_failed", template_name=name, error=str(exc))
            self.failed_templates.append((target_path, str(exc)))
            return False

        if not isinstance(raw_json, str):
            error_message = f"export_template_json returned non-string for {name!r}"
            _logger.warning("builtin_export_invalid_type", template_name=name)
            self.failed_templates.append((target_path, error_message))
            return False

        try:
            target_path.write_text(raw_json, encoding="utf-8")
        except OSError as exc:
            _logger.exception(
                "builtin_template_write_failed",
                template_name=name,
                path=str(target_path),
            )
            self.failed_templates.append((target_path, str(exc)))
            return False

        _logger.info(
            "builtin_template_file_written",
            template_name=name,
            path=str(target_path),
            size=len(raw_json),
        )
        return True

    def list_all_templates(self) -> list[TemplateInfo]:
        """List all available templates (built-in and user).

        Returns:
            list[TemplateInfo]: List of template metadata sorted by name.
        """
        templates: list[TemplateInfo] = []

        for json_path in self._builtin_dir.rglob("*.json"):
            info = self._parse_template_file(json_path, is_builtin=True)
            if info is not None:
                templates.append(info)

        for json_path in self._user_dir.rglob("*.json"):
            dsl_path = json_path.with_suffix(".hexpat")
            dsl = dsl_path if dsl_path.exists() else None
            info = self._parse_template_file(json_path, is_builtin=False, dsl_path=dsl)
            if info is not None:
                templates.append(info)

        templates.sort(key=lambda t: t.name)
        return templates

    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Convert a template name to a safe filesystem filename.

        Args:
            name: Template name.

        Returns:
            str: Sanitized name with only alphanumeric, underscore, and hyphen characters.

        Raises:
            ValueError: If the sanitized name is empty.
        """
        safe = "".join(c if c.isalnum() or c in {"_", "-"} else "_" for c in name)
        if not safe.strip("_"):
            msg = f"template name produces an empty filename after sanitization: {name!r}"
            _logger.warning("template_name_sanitization_empty", template_name=name)
            raise ValueError(msg)
        return safe

    def save_user_template(
        self,
        name: str,
        json_str: str,
        dsl_source: str | None = None,
    ) -> Path:
        """Save a user-defined template.

        Writes the JSON template (and the optional DSL source) to disk
        and only emits ``user_template_file_written`` /
        ``user_template_dsl_file_written`` after the corresponding
        ``Path.write_text`` call returns successfully. Failures are
        logged at ``error`` as ``user_template_write_failed`` /
        ``user_template_dsl_write_failed`` and re-raised so callers can
        react.

        Args:
            name: Template name.
            json_str: JSON template content.
            dsl_source: Optional DSL source to save alongside.

        Returns:
            Path: Path to the saved JSON file.

        Raises:
            ValueError: If the name is empty or produces an empty filename.
            OSError: If writing the JSON or DSL file fails.
        """
        if not name.strip():
            msg = "template name must not be empty"
            _logger.warning("user_template_save_empty_name")
            raise ValueError(msg)
        self.ensure_directories()
        safe_name = self._sanitize_name(name)
        json_path = self._user_dir / f"{safe_name}.json"
        try:
            json_path.write_text(json_str, encoding="utf-8")
        except OSError as exc:
            _logger.warning(
                "user_template_write_failed",
                template_name=name,
                path=str(json_path),
                error=str(exc),
            )
            raise
        _logger.info(
            "user_template_file_written",
            template_name=name,
            path=str(json_path),
            size=len(json_str),
        )
        _logger.info("user_template_saved", template_name=name, path=str(json_path))

        if dsl_source is not None:
            dsl_path = self._user_dir / f"{safe_name}.hexpat"
            try:
                dsl_path.write_text(dsl_source, encoding="utf-8")
            except OSError as exc:
                _logger.warning(
                    "user_template_dsl_write_failed",
                    template_name=name,
                    path=str(dsl_path),
                    error=str(exc),
                )
                raise
            _logger.info(
                "user_template_dsl_file_written",
                template_name=name,
                path=str(dsl_path),
                size=len(dsl_source),
            )

        return json_path

    @staticmethod
    def load_template(path: Path) -> str:
        """Load a template JSON from disk.

        Args:
            path: Path to the JSON template file.

        Returns:
            str: JSON content string.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not path.exists():
            msg = f"template file not found: {path}"
            _logger.warning("template_load_file_missing", path=str(path))
            raise FileNotFoundError(msg)
        return path.read_text(encoding="utf-8")

    def delete_user_template(self, name: str) -> bool:
        """Delete a user-defined template.

        Args:
            name: Template name.

        Returns:
            bool: True if the template was deleted.

        Raises:
            ValueError: If the name is empty.
        """
        if not name.strip():
            msg = "template name must not be empty"
            _logger.warning("user_template_delete_empty_name")
            raise ValueError(msg)
        safe_name = self._sanitize_name(name)
        json_path = self._user_dir / f"{safe_name}.json"
        dsl_path = self._user_dir / f"{safe_name}.hexpat"
        deleted = False
        if json_path.exists():
            _logger.info(
                "user_template_json_unlink",
                template_name=name,
                path=str(json_path),
            )
            json_path.unlink()
            deleted = True
        if dsl_path.exists():
            _logger.info(
                "user_template_dsl_unlink",
                template_name=name,
                path=str(dsl_path),
            )
            dsl_path.unlink()
        if deleted:
            _logger.info("user_template_deleted", template_name=name)
        return deleted

    def _parse_template_file(
        self,
        json_path: Path,
        *,
        is_builtin: bool,
        dsl_path: Path | None = None,
    ) -> TemplateInfo | None:
        """Parse a template JSON file to extract metadata.

        Logs any failure at ``warning`` and records a ``(path, error)``
        entry in ``self.failed_templates`` instead of silently returning
        ``None``.

        Args:
            json_path: Path to the JSON file.
            is_builtin: Whether this is a built-in template.
            dsl_path: Optional path to accompanying DSL file.

        Returns:
            TemplateInfo | None: Parsed template info, or ``None`` if the
                file could not be read or parsed.
        """
        try:
            content = json_path.read_text(encoding="utf-8")
            data = json.loads(content)
            name = data.get("name", json_path.stem)
            description = data.get("description", "")
            category = data.get("category", "") or json_path.parent.name.upper()
            return TemplateInfo(
                name=name,
                description=description,
                category=category,
                is_builtin=is_builtin,
                json_path=json_path,
                dsl_path=dsl_path,
            )
        except (OSError, ValueError, KeyError) as exc:
            _logger.warning(
                "template_parse_failed",
                path=str(json_path),
                error=str(exc),
            )
            self.failed_templates.append((json_path, str(exc)))
            return None

    @property
    def patterns_dir(self) -> Path:
        """The community .hexpat patterns directory.

        Returns:
            Path: The vendor community patterns directory path.
        """
        project_root = Path(__file__).resolve().parents[3]
        return project_root / "vendor" / "community-patterns" / "patterns"

    def get_pattern_registry(self) -> PatternRegistry | None:
        """Get or create the PatternRegistry for .hexpat pattern discovery.

        Returns:
            PatternRegistry | None: A PatternRegistry instance, or None if
                unavailable.
        """
        if self._pattern_registry is not None:
            return self._pattern_registry

        if not _hexpat_registry_available or _PatternRegistry is None:
            _logger.debug("hexpat_registry_unavailable")
            return None

        pattern_dirs: list[Path] = []
        patterns_root = self.patterns_dir
        if patterns_root.exists():
            pattern_dirs.append(patterns_root)

        self._pattern_registry = _PatternRegistry(pattern_dirs)
        return self._pattern_registry

    def list_hexpat_patterns(self) -> list[dict[str, str]]:
        """List all discovered .hexpat patterns with metadata.

        Returns:
            list[dict[str, str]]: List of dicts with name, description,
                category, and file_path keys.
        """
        registry = self.get_pattern_registry()
        if registry is None:
            return []

        patterns = registry.list_patterns()
        return [
            {
                "name": pattern.name,
                "description": pattern.description or "",
                "category": pattern.category,
                "file_path": str(pattern.file_path),
            }
            for pattern in patterns
        ]

    def list_hexpat_by_category(self) -> dict[str, list[dict[str, str]]]:
        """List .hexpat patterns grouped by category.

        Returns:
            dict[str, list[dict[str, str]]]: Category name to list of pattern dicts.
        """
        registry = self.get_pattern_registry()
        if registry is None:
            return {}

        by_cat = registry.list_by_category()
        result: dict[str, list[dict[str, str]]] = {
            category: [
                {
                    "name": p.name,
                    "description": p.description or "",
                    "file_path": str(p.file_path),
                }
                for p in patterns
            ]
            for category, patterns in by_cat.items()
        }
        return result
