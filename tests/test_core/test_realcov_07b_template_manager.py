# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :mod:`intellicrack.core.template_manager`.

The audit flagged ``template_manager.py`` as having zero test coverage. These
tests exercise the full public API against real artifacts:

* :meth:`TemplateManager.bootstrap_builtins` runs against a real
  ``intellicrack_hexcore.HexDocument`` and exports the genuine built-in
  template set to disk.
* Save / load / delete / list round-trip real JSON template content.
* :meth:`TemplateManager.list_hexpat_patterns` and the pattern registry are
  validated against the committed ``vendor/community-patterns`` collection.

No template operation is mocked; every assertion is against data produced by
the real component under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intellicrack.core.template_manager import TemplateInfo, TemplateManager


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module is required for HexDocument bootstrap",
)


def _make_manager(tmp_path: Path) -> TemplateManager:
    """Create a TemplateManager rooted under a temporary config dir.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        TemplateManager: A manager whose template tree lives under ``tmp_path``.
    """
    return TemplateManager(tmp_path / "config")


class TestDirectoryAndSaveRoundTrip:
    """Directory creation and user-template persistence must round-trip."""

    def test_ensure_directories_creates_full_tree(self, tmp_path: Path) -> None:
        """``ensure_directories`` materialises builtin category and user dirs.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        manager.ensure_directories()
        base = tmp_path / "config" / "templates"
        assert (base / "user").is_dir()
        for category in ("pe", "elf", "macho", "zip", "common"):
            assert (base / "builtin" / category).is_dir()

    def test_save_then_load_user_template_preserves_content(self, tmp_path: Path) -> None:
        """A saved user template loads back byte-for-byte.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        payload = json.dumps(
            {
                "name": "MyHeader",
                "description": "custom header",
                "category": "Custom",
                "fields": [{"name": "magic", "field_type": {"type": "UInt32"}}],
            },
        )
        saved = manager.save_user_template("MyHeader", payload)
        assert saved.exists()
        assert TemplateManager.load_template(saved) == payload

    def test_save_user_template_writes_dsl_sidecar(self, tmp_path: Path) -> None:
        """When DSL source is given, the ``.hexpat`` sidecar is written.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        dsl = "struct MyHeader { u32 magic; };"
        saved = manager.save_user_template("MyHeader", '{"name": "MyHeader"}', dsl_source=dsl)
        sidecar = saved.with_suffix(".hexpat")
        assert sidecar.read_text(encoding="utf-8") == dsl

    def test_save_user_template_rejects_empty_name(self, tmp_path: Path) -> None:
        """An empty/whitespace name raises ``ValueError``.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        with pytest.raises(ValueError, match="must not be empty"):
            manager.save_user_template("   ", "{}")

    def test_delete_user_template_removes_json_and_dsl(self, tmp_path: Path) -> None:
        """Deleting a user template removes both the JSON and DSL files.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        saved = manager.save_user_template("Tmp", '{"name": "Tmp"}', dsl_source="struct Tmp { u8 a; };")
        assert manager.delete_user_template("Tmp") is True
        assert not saved.exists()
        assert not saved.with_suffix(".hexpat").exists()

    def test_delete_missing_template_returns_false(self, tmp_path: Path) -> None:
        """Deleting a non-existent template reports ``False``.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        manager.ensure_directories()
        assert manager.delete_user_template("does_not_exist") is False

    def test_load_missing_template_raises(self, tmp_path: Path) -> None:
        """Loading a missing path raises ``FileNotFoundError``.

        Args:
            tmp_path: Per-test temporary directory.
        """
        with pytest.raises(FileNotFoundError):
            TemplateManager.load_template(tmp_path / "absent.json")


class TestListAndParse:
    """Listing and parsing must read real on-disk template metadata."""

    def test_list_all_templates_parses_user_metadata(self, tmp_path: Path) -> None:
        """A listed user template carries its parsed name/description/category.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        manager.save_user_template(
            "Widget",
            json.dumps({"name": "Widget", "description": "a widget", "category": "Custom"}),
        )
        templates = manager.list_all_templates()
        widget = next(t for t in templates if t.name == "Widget")
        assert isinstance(widget, TemplateInfo)
        assert widget.description == "a widget"
        assert widget.category == "Custom"
        assert widget.is_builtin is False

    def test_list_all_templates_sorted_by_name(self, tmp_path: Path) -> None:
        """Listed templates are sorted by their template name.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        manager.save_user_template("Zeta", json.dumps({"name": "Zeta"}))
        manager.save_user_template("Alpha", json.dumps({"name": "Alpha"}))
        names = [t.name for t in manager.list_all_templates()]
        assert names == sorted(names)

    def test_parse_failure_recorded_for_invalid_json(self, tmp_path: Path) -> None:
        """A malformed JSON template is skipped and recorded as a failure.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        manager.ensure_directories()
        bad = tmp_path / "config" / "templates" / "user" / "broken.json"
        bad.write_text("{ not valid json", encoding="utf-8")
        templates = manager.list_all_templates()
        assert all(t.name != "broken" or t.json_path != bad for t in templates)
        assert any(path == bad for path, _ in manager.failed_templates)


class TestBootstrapBuiltins:
    """Bootstrap must export the real native built-in template set to disk."""

    def test_bootstrap_exports_real_builtin_templates(self, tmp_path: Path) -> None:
        """Bootstrapping a real HexDocument writes builtin JSON files to disk.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        document = hexcore.HexDocument.open_bytes(b"MZ" + b"\x00" * 256)
        expected = document.list_templates_detailed()
        if not expected:
            pytest.skip("native HexDocument exposes no built-in templates")

        manager.bootstrap_builtins(document)
        assert not manager.failed_templates

        listed = manager.list_all_templates()
        listed_names = {t.name for t in listed}
        expected_names = {entry[0] for entry in expected}
        assert expected_names.issubset(listed_names)
        assert all(t.is_builtin for t in listed if t.name in expected_names)

    def test_bootstrap_written_json_is_valid_and_matches_export(self, tmp_path: Path) -> None:
        """Each bootstrapped file is valid JSON matching the native export.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        document = hexcore.HexDocument.open_bytes(b"\x7fELF" + b"\x00" * 256)
        expected = document.list_templates_detailed()
        if not expected:
            pytest.skip("native HexDocument exposes no built-in templates")

        manager.bootstrap_builtins(document)
        first_name = expected[0][0]
        match = next(t for t in manager.list_all_templates() if t.name == first_name)
        on_disk = json.loads(match.json_path.read_text(encoding="utf-8"))
        from_native = json.loads(document.export_template_json(first_name))
        assert on_disk == from_native

    def test_bootstrap_is_idempotent(self, tmp_path: Path) -> None:
        """A second bootstrap is a no-op when all templates already exist.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        document = hexcore.HexDocument.open_bytes(b"MZ" + b"\x00" * 256)
        if not document.list_templates_detailed():
            pytest.skip("native HexDocument exposes no built-in templates")
        manager.bootstrap_builtins(document)
        count_first = len(manager.list_all_templates())
        manager.bootstrap_builtins(document)
        assert len(manager.list_all_templates()) == count_first


class TestHexPatPatternRegistry:
    """Pattern discovery must surface the committed community patterns."""

    def test_patterns_dir_points_at_committed_vendor_collection(self, tmp_path: Path) -> None:
        """The patterns directory resolves to the vendor community collection.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        patterns_dir = manager.patterns_dir
        assert patterns_dir.name == "patterns"
        assert patterns_dir.parent.name == "community-patterns"

    def test_list_hexpat_patterns_discovers_real_files(self, tmp_path: Path) -> None:
        """Listing real ``.hexpat`` patterns yields complete metadata dicts.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        if not manager.patterns_dir.exists():
            pytest.skip("vendor community patterns are not checked out")

        patterns = manager.list_hexpat_patterns()
        assert len(patterns) > 1
        for entry in patterns:
            assert entry["name"]
            assert Path(entry["file_path"]).suffix == ".hexpat"
            assert Path(entry["file_path"]).exists()

    def test_get_pattern_registry_is_memoised(self, tmp_path: Path) -> None:
        """Repeated registry access returns the same cached instance.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        first = manager.get_pattern_registry()
        if first is None:
            pytest.skip("pattern registry backend is unavailable")
        assert manager.get_pattern_registry() is first

    def test_list_hexpat_by_category_groups_real_patterns(self, tmp_path: Path) -> None:
        """Patterns grouped by category cover the same files as the flat list.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = _make_manager(tmp_path)
        if not manager.patterns_dir.exists():
            pytest.skip("vendor community patterns are not checked out")

        flat = manager.list_hexpat_patterns()
        grouped = manager.list_hexpat_by_category()
        if not flat:
            pytest.skip("no community patterns discovered")
        grouped_total = sum(len(items) for items in grouped.values())
        assert grouped_total == len(flat)
        assert all(category for category in grouped)
