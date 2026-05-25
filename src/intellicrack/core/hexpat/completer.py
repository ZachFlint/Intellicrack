# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Type-name completion source for the HexPat pattern editor.

Provides :class:`HexPatCompleter`, a backend-agnostic identifier provider that
combines built-in primitive type names from :class:`BuiltinTypes` with the
user-declared identifiers harvested from a :class:`TypeRegistry` produced by
the most recent successful interpreter run. The UI consumes its output via a
``QCompleter`` driven by ``QStringListModel``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.core.hexpat.type_system import BuiltinTypes
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.hexpat.type_system import TypeRegistry


_logger = get_logger(__name__)


class HexPatCompleter:
    """Type-name completion source for the HexPat pattern editor.

    Tracks the union of built-in primitive type names (always present) and
    user-declared type names harvested from a :class:`TypeRegistry`. Refresh
    the user-name set after every successful pattern execution by calling
    :meth:`update_from_registry`.
    """

    def __init__(self) -> None:
        """Initialize the completer with an empty user-name set."""
        self._user_names: frozenset[str] = frozenset()

    def update_from_registry(self, registry: TypeRegistry) -> None:
        """Refresh the user-name set from a :class:`TypeRegistry` snapshot.

        Args:
            registry: The :class:`TypeRegistry` produced by the most recent
                successful interpreter execution.
        """
        self._user_names = registry.user_type_names()
        _logger.debug("hexpat_completer_user_names_updated", count=len(self._user_names))

    def all_type_names(self) -> list[str]:
        """Return every identifier this completer can offer.

        Returns:
            list[str]: Lexicographically sorted list combining built-in
                primitive type names with user-declared identifiers.
        """
        return sorted(BuiltinTypes.all_names() | self._user_names)

    def complete(self, prefix: str) -> list[str]:
        """Return the case-insensitive prefix matches for ``prefix``.

        An empty ``prefix`` returns every known identifier, matching the
        Qt ``QCompleter`` convention for an unfiltered popup.

        Args:
            prefix: User-typed identifier fragment to match against.

        Returns:
            list[str]: Sorted list of matching identifier names.
        """
        if not prefix:
            return self.all_type_names()
        lowered = prefix.lower()
        candidates: frozenset[str] = BuiltinTypes.all_names() | self._user_names
        return sorted(n for n in candidates if n.lower().startswith(lowered))
