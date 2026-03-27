# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument template registration and application."""

from __future__ import annotations

import json
import struct
from typing import Any

import pytest


PE_LFANEW_VALUE = 0x80
PE_E_MAGIC_DECIMAL = 23117
PE_E_MAGIC_HEX = "5A4D"

_CUSTOM_TEMPLATE_JSON = json.dumps(
    {
        "name": "TestStruct",
        "description": "Test structure for E2E validation",
        "default_endianness": "little",
        "category": "test",
        "fields": [
            {
                "name": "magic",
                "field_type": {"type": "UInt16"},
                "description": "Magic number",
            },
            {
                "name": "version",
                "field_type": {"type": "UInt32"},
                "description": "Version field",
            },
        ],
    }
)


class TestListTemplates:
    """Tests for the list_templates API returning (name, description) pairs."""

    def test_returns_nonempty_list(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify list_templates returns at least one entry.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        templates: list[tuple[str, str]] = doc.list_templates()
        assert len(templates) > 0

    def test_entries_are_name_description_pairs(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify each entry is a 2-tuple of strings.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        templates: list[tuple[str, str]] = doc.list_templates()
        for entry in templates:
            assert len(entry) == 2
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], str)
            assert len(entry[0]) > 0

    def test_image_dos_header_present(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify IMAGE_DOS_HEADER is in the built-in template list.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "IMAGE_DOS_HEADER" in names

    def test_elf_template_present(self, hexcore: Any, elf_bytes: bytes) -> None:
        """Verify Elf64_Ehdr built-in template is always registered.

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "Elf64_Ehdr" in names

    def test_zip_template_present(self, hexcore: Any, zip_bytes: bytes) -> None:
        """Verify ZIP_LOCAL_FILE_HEADER built-in template is always registered.

        Args:
            hexcore: The native module fixture.
            zip_bytes: Minimal ZIP file bytes.
        """
        doc = hexcore.HexDocument.open_bytes(zip_bytes)
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "ZIP_LOCAL_FILE_HEADER" in names


class TestListTemplatesDetailed:
    """Tests for the list_templates_detailed API returning 4-tuples."""

    def test_returns_nonempty_list(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify list_templates_detailed returns at least one entry.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        detailed: list[tuple[str, str, str, int]] = doc.list_templates_detailed()
        assert len(detailed) > 0

    def test_entries_are_four_tuples(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify each entry is (name, description, category, field_count).

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        detailed: list[tuple[str, str, str, int]] = doc.list_templates_detailed()
        for entry in detailed:
            assert len(entry) == 4
            name, description, category, field_count = entry
            assert isinstance(name, str)
            assert isinstance(description, str)
            assert isinstance(category, str)
            assert isinstance(field_count, int)

    def test_dos_header_field_count_positive(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify IMAGE_DOS_HEADER has a positive field count.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        detailed: list[tuple[str, str, str, int]] = doc.list_templates_detailed()
        dos_entries = [(n, d, c, fc) for n, d, c, fc in detailed if n == "IMAGE_DOS_HEADER"]
        assert len(dos_entries) == 1
        _, _, category, field_count = dos_entries[0]
        assert field_count > 0
        assert category == "PE"

    def test_elf64_field_count_positive(self, hexcore: Any, elf_bytes: bytes) -> None:
        """Verify Elf64_Ehdr has a positive field count and ELF category.

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        detailed: list[tuple[str, str, str, int]] = doc.list_templates_detailed()
        elf_entries = [(n, d, c, fc) for n, d, c, fc in detailed if n == "Elf64_Ehdr"]
        assert len(elf_entries) == 1
        _, _, category, field_count = elf_entries[0]
        assert field_count > 0
        assert category == "ELF"

    def test_zip_template_field_count_positive(self, hexcore: Any, zip_bytes: bytes) -> None:
        """Verify ZIP_LOCAL_FILE_HEADER has a positive field count.

        Args:
            hexcore: The native module fixture.
            zip_bytes: Minimal ZIP file bytes.
        """
        doc = hexcore.HexDocument.open_bytes(zip_bytes)
        detailed: list[tuple[str, str, str, int]] = doc.list_templates_detailed()
        zip_entries = [(n, d, c, fc) for n, d, c, fc in detailed if n == "ZIP_LOCAL_FILE_HEADER"]
        assert len(zip_entries) == 1
        _, _, category, field_count = zip_entries[0]
        assert field_count > 0
        assert category == "ZIP"


class TestApplyPETemplate:
    """Tests for applying the IMAGE_DOS_HEADER template to PE binary data."""

    def test_apply_returns_nonempty_fields(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify apply_template on IMAGE_DOS_HEADER returns parsed fields.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        assert len(fields) > 0

    def test_first_field_is_e_magic(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify the first parsed field is named e_magic.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        assert fields[0]["name"] == "e_magic"

    def test_e_magic_contains_mz_value(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify e_magic display value contains the MZ magic (23117 or 5A4D).

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        e_magic = fields[0]
        display: str = e_magic["display_value"]
        assert str(PE_E_MAGIC_DECIMAL) in display or PE_E_MAGIC_HEX in display

    def test_e_magic_offset_is_zero(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify e_magic is parsed at offset 0.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        assert fields[0]["offset"] == 0

    def test_e_lfanew_field_exists(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify e_lfanew field is present in parsed output.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        names = [f["name"] for f in fields]
        assert "e_lfanew" in names

    def test_e_lfanew_has_correct_value(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify e_lfanew display value matches the 0x80 offset in the PE fixture.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        lfanew_fields = [f for f in fields if f["name"] == "e_lfanew"]
        assert len(lfanew_fields) == 1
        display: str = lfanew_fields[0]["display_value"]
        assert str(PE_LFANEW_VALUE) in display

    def test_fields_have_required_keys(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify every returned field dict contains name, offset, size, display_value.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        for field in fields:
            assert "name" in field
            assert "offset" in field
            assert "size" in field
            assert "display_value" in field


class TestApplyELFTemplate:
    """Tests for applying the Elf64_Ehdr template to ELF64 binary data."""

    def test_apply_returns_fields(self, hexcore: Any, elf_bytes: bytes) -> None:
        """Verify Elf64_Ehdr template parses the ELF binary successfully.

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("Elf64_Ehdr", 0)
        assert len(fields) > 0

    def test_first_field_is_e_ident(self, hexcore: Any, elf_bytes: bytes) -> None:
        """Verify the first parsed field is named e_ident.

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("Elf64_Ehdr", 0)
        assert fields[0]["name"] == "e_ident"

    def test_e_ident_contains_elf_magic_hex(self, hexcore: Any, elf_bytes: bytes) -> None:
        """Verify e_ident display value contains 7F 45 4C 46 (ELF magic).

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("Elf64_Ehdr", 0)
        e_ident_display: str = fields[0]["display_value"]
        assert "7F" in e_ident_display
        assert "45" in e_ident_display
        assert "4C" in e_ident_display
        assert "46" in e_ident_display

    def test_e_ident_size_is_16(self, hexcore: Any, elf_bytes: bytes) -> None:
        """Verify e_ident field has size 16 as per ELF specification.

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("Elf64_Ehdr", 0)
        assert fields[0]["size"] == 16


class TestApplyZIPTemplate:
    """Tests for applying the ZIP_LOCAL_FILE_HEADER template to ZIP binary data."""

    def test_apply_returns_fields(self, hexcore: Any, zip_bytes: bytes) -> None:
        """Verify ZIP_LOCAL_FILE_HEADER template parses the ZIP binary successfully.

        Args:
            hexcore: The native module fixture.
            zip_bytes: Minimal ZIP file bytes.
        """
        doc = hexcore.HexDocument.open_bytes(zip_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("ZIP_LOCAL_FILE_HEADER", 0)
        assert len(fields) > 0

    def test_first_field_is_signature(self, hexcore: Any, zip_bytes: bytes) -> None:
        """Verify the first parsed field is named signature.

        Args:
            hexcore: The native module fixture.
            zip_bytes: Minimal ZIP file bytes.
        """
        doc = hexcore.HexDocument.open_bytes(zip_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("ZIP_LOCAL_FILE_HEADER", 0)
        assert fields[0]["name"] == "signature"

    def test_signature_contains_pk_magic(self, hexcore: Any, zip_bytes: bytes) -> None:
        """Verify the signature field display value contains the PK magic (0x04034B50).

        Args:
            hexcore: The native module fixture.
            zip_bytes: Minimal ZIP file bytes.
        """
        doc = hexcore.HexDocument.open_bytes(zip_bytes)
        fields: list[dict[str, Any]] = doc.apply_template("ZIP_LOCAL_FILE_HEADER", 0)
        sig_display: str = fields[0]["display_value"]
        assert "67324752" in sig_display or "04034B50" in sig_display or "4B50" in sig_display.upper()


class TestRegisterCustomTemplate:
    """Tests for registering and using a custom JSON-defined template."""

    def test_register_returns_template_name(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify register_json_template returns the template name from JSON.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        name: str = doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        assert name == "TestStruct"

    def test_custom_template_appears_in_list(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify the custom template appears in list_templates after registration.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "TestStruct" in names

    def test_apply_custom_template_parses_fields(self, hexcore: Any) -> None:
        """Verify applying the custom template parses the expected fields.

        Args:
            hexcore: The native module fixture.
        """
        data = bytearray(6)
        struct.pack_into("<H", data, 0, 0xABCD)
        struct.pack_into("<I", data, 2, 0x12345678)
        doc = hexcore.HexDocument.open_bytes(bytes(data))
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        fields: list[dict[str, Any]] = doc.apply_template("TestStruct", 0)
        assert len(fields) == 2
        assert fields[0]["name"] == "magic"
        assert fields[1]["name"] == "version"

    def test_custom_template_magic_value_correct(self, hexcore: Any) -> None:
        """Verify the parsed magic field contains the expected value.

        Args:
            hexcore: The native module fixture.
        """
        data = bytearray(6)
        struct.pack_into("<H", data, 0, 0xABCD)
        struct.pack_into("<I", data, 2, 0x12345678)
        doc = hexcore.HexDocument.open_bytes(bytes(data))
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        fields: list[dict[str, Any]] = doc.apply_template("TestStruct", 0)
        magic_display: str = fields[0]["display_value"]
        assert "43981" in magic_display or "ABCD" in magic_display

    def test_custom_template_version_value_correct(self, hexcore: Any) -> None:
        """Verify the parsed version field contains the expected value.

        Args:
            hexcore: The native module fixture.
        """
        data = bytearray(6)
        struct.pack_into("<H", data, 0, 0xABCD)
        struct.pack_into("<I", data, 2, 0x12345678)
        doc = hexcore.HexDocument.open_bytes(bytes(data))
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        fields: list[dict[str, Any]] = doc.apply_template("TestStruct", 0)
        version_display: str = fields[1]["display_value"]
        assert "305419896" in version_display or "12345678" in version_display


class TestRemoveTemplate:
    """Tests for removing templates from the document registry."""

    def test_remove_custom_template_returns_true(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify remove_template returns True when the template exists.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        result: bool = doc.remove_template("TestStruct")
        assert result is True

    def test_removed_template_absent_from_list(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify removed template no longer appears in list_templates.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        doc.remove_template("TestStruct")
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "TestStruct" not in names

    def test_remove_nonexistent_returns_false(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify remove_template returns False when the template does not exist.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        result: bool = doc.remove_template("__DOES_NOT_EXIST__")
        assert result is False

    def test_builtin_template_removable(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify a built-in template can be removed and disappears from the list.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        result: bool = doc.remove_template("IMAGE_DOS_HEADER")
        assert result is True
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "IMAGE_DOS_HEADER" not in names


class TestExportTemplate:
    """Tests for exporting registered templates as JSON."""

    def test_export_builtin_returns_valid_json(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify export_template_json returns parseable JSON for a built-in template.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        exported: str = doc.export_template_json("IMAGE_DOS_HEADER")
        parsed = json.loads(exported)
        assert isinstance(parsed, dict)

    def test_export_contains_template_name(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify the exported JSON contains the correct template name.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        exported: str = doc.export_template_json("IMAGE_DOS_HEADER")
        assert "IMAGE_DOS_HEADER" in exported

    def test_export_contains_field_names(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify the exported JSON contains expected field names like e_magic.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        exported: str = doc.export_template_json("IMAGE_DOS_HEADER")
        assert "e_magic" in exported
        assert "e_lfanew" in exported

    def test_exported_json_can_be_reregistered(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify exported JSON can be removed and re-registered with equivalent behavior.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        exported: str = doc.export_template_json("IMAGE_DOS_HEADER")
        doc.remove_template("IMAGE_DOS_HEADER")
        name: str = doc.register_json_template(exported)
        assert name == "IMAGE_DOS_HEADER"
        templates: list[tuple[str, str]] = doc.list_templates()
        names = [t[0] for t in templates]
        assert "IMAGE_DOS_HEADER" in names

    def test_roundtrip_produces_equivalent_parse(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify re-registered template produces identical field parse results.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        fields_before: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        exported: str = doc.export_template_json("IMAGE_DOS_HEADER")
        doc.remove_template("IMAGE_DOS_HEADER")
        doc.register_json_template(exported)
        fields_after: list[dict[str, Any]] = doc.apply_template("IMAGE_DOS_HEADER", 0)
        assert len(fields_before) == len(fields_after)
        for before, after in zip(fields_before, fields_after, strict=False):
            assert before["name"] == after["name"]
            assert before["display_value"] == after["display_value"]
            assert before["offset"] == after["offset"]
            assert before["size"] == after["size"]

    def test_export_custom_template(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify export_template_json works for a custom-registered template.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        doc.register_json_template(_CUSTOM_TEMPLATE_JSON)
        exported: str = doc.export_template_json("TestStruct")
        parsed = json.loads(exported)
        assert parsed["name"] == "TestStruct"
        field_names = [f["name"] for f in parsed["fields"]]
        assert "magic" in field_names
        assert "version" in field_names


class TestApplyInvalidTemplate:
    """Tests for error handling when applying non-existent templates."""

    def test_nonexistent_template_raises(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify apply_template raises an exception for an unknown template name.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        with pytest.raises((OSError, RuntimeError, KeyError, ValueError)):
            doc.apply_template("__NO_SUCH_TEMPLATE__", 0)

    def test_empty_template_name_raises(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify apply_template raises an exception when name is an empty string.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        with pytest.raises((OSError, RuntimeError, KeyError, ValueError)):
            doc.apply_template("", 0)

    def test_export_nonexistent_raises(self, hexcore: Any, pe_bytes: bytes) -> None:
        """Verify export_template_json raises for a template name that does not exist.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        with pytest.raises((OSError, RuntimeError, KeyError, ValueError)):
            doc.export_template_json("__NO_SUCH_TEMPLATE__")


class TestTemplateOnWrongData:
    """Tests for template behavior when applied to binary data of the wrong format."""

    def test_pe_template_on_elf_data_parses_or_raises(
        self, hexcore: Any, elf_bytes: bytes
    ) -> None:
        """Verify IMAGE_DOS_HEADER on ELF data either parses with wrong values or raises.

        If it parses, the e_magic field must NOT contain the MZ magic string.

        Args:
            hexcore: The native module fixture.
            elf_bytes: Minimal ELF64 binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(elf_bytes)
        parsed_successfully = False
        wrong_data_fields: list[dict[str, Any]] = []
        try:
            wrong_data_fields = doc.apply_template("IMAGE_DOS_HEADER", 0)
            parsed_successfully = True
        except Exception as _exc:
            parsed_successfully = False
        if parsed_successfully:
            assert len(wrong_data_fields) > 0
            e_magic_fields = [f for f in wrong_data_fields if f["name"] == "e_magic"]
            assert len(e_magic_fields) == 1
            display: str = e_magic_fields[0]["display_value"]
            assert str(PE_E_MAGIC_DECIMAL) not in display

    def test_elf_template_on_pe_data_parses_or_raises(
        self, hexcore: Any, pe_bytes: bytes
    ) -> None:
        """Verify Elf64_Ehdr on PE data either parses with wrong values or raises.

        If it parses, the e_ident field must NOT contain 7F 45 4C 46.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        parsed_successfully = False
        wrong_data_fields: list[dict[str, Any]] = []
        try:
            wrong_data_fields = doc.apply_template("Elf64_Ehdr", 0)
            parsed_successfully = True
        except Exception as _exc:
            parsed_successfully = False
        if parsed_successfully:
            assert len(wrong_data_fields) > 0
            e_ident_fields = [f for f in wrong_data_fields if f["name"] == "e_ident"]
            assert len(e_ident_fields) == 1
            display: str = e_ident_fields[0]["display_value"]
            assert "7F 45 4C 46" not in display

    def test_dos_header_on_too_short_data_raises(self, hexcore: Any) -> None:
        """Verify IMAGE_DOS_HEADER raises when data is shorter than the 64-byte structure.

        Args:
            hexcore: The native module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(10))
        with pytest.raises((OSError, RuntimeError, KeyError, ValueError)):
            doc.apply_template("IMAGE_DOS_HEADER", 0)

    def test_apply_at_nonzero_offset_within_bounds(self, hexcore: Any, pe_bytes: bytes) -> None:
        r"""Verify apply_template respects the offset parameter when data is present.

        Applying IMAGE_FILE_HEADER at PE_SIGNATURE_OFFSET + 4 (after "PE\x00\x00") should parse.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        coff_offset = PE_LFANEW_VALUE + 4
        fields: list[dict[str, Any]] = doc.apply_template("IMAGE_FILE_HEADER", coff_offset)
        assert len(fields) > 0
        assert fields[0]["name"] == "Machine"
        assert fields[0]["offset"] == coff_offset
