# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Data inspector mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any, cast

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem

from intellicrack.ui.panels.hex_editor._base import logger


class DataInspectorMixin:
    """Mixin providing data inspector functionality for the hex editor panel."""

    _data_inspector_tree: QTreeWidget | None
    _document: Any | None
    document: Any | None

    def _update_data_inspector(self, offset: int) -> None:
        """Update the data inspector tree for the given offset.

        Args:
            offset: Byte offset to inspect.
        """
        if self._data_inspector_tree is None or self.document is None:
            return

        self._data_inspector_tree.clear()
        try:
            result = self.document.inspect_at(offset)
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)

            display_order = [
                "int8",
                "uint8",
                "ascii_char",
                "utf8_char",
                "int16_le",
                "uint16_le",
                "int16_be",
                "uint16_be",
                "int32_le",
                "uint32_le",
                "int32_be",
                "uint32_be",
                "float32_le",
                "float32_be",
                "int64_le",
                "uint64_le",
                "int64_be",
                "uint64_be",
                "float64_le",
                "float64_be",
                "unix_timestamp",
                "dos_date",
                "dos_time",
                "filetime",
            ]

            for key in display_order:
                if key in typed_result:
                    item = QTreeWidgetItem([key, str(typed_result[key])])
                    self._data_inspector_tree.addTopLevelItem(item)

            for key, val in sorted(typed_result.items()):
                if key not in display_order:
                    item = QTreeWidgetItem([key, str(val)])
                    self._data_inspector_tree.addTopLevelItem(item)

        except (AttributeError, ValueError, TypeError) as exc:
            logger.debug("inspector_update_failed", error=str(exc))
