# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""``require_encodable`` must itself be able to fail when the codec cannot encode a value.

The check it replaced, ``self.require(bool(json.dumps(result.value)), ...)``,
could never turn red: ``json.dumps`` never returns a falsy string for a value
it *can* encode, and raises rather than returning anything for a value it
*cannot* -- so the assertion's condition was always true whenever it was
reached, and a genuinely unencodable value would instead escape as a bare,
unattributed ``TypeError``. These tests drive ``require_encodable`` with a
real unencodable Python object and check that the failure it produces is an
``AssertionError`` naming both the operation and the offending type, not the
raw ``TypeError`` the old check could never turn into anything better.
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING, cast

from hexbench.tests._support import Assertions, require_encodable


if TYPE_CHECKING:
    from hexbench.codec import JsonValue


class RequireEncodableTests(Assertions, unittest.TestCase):
    """``require_encodable`` against values the JSON codec can and cannot render."""

    def test_a_json_safe_value_passes_without_raising(self) -> None:
        """An ordinary JSON-safe value must not be reported as unencodable."""
        safe = cast("JsonValue", {"offset": 0, "kinds": [1, 2, 3]})
        try:
            require_encodable("digram_matrix", safe)
        except AssertionError as exc:
            self.fail(f"a JSON-safe value was rejected as unencodable: {exc}")

    def test_an_unencodable_value_raises_assertion_error_not_a_bare_type_error(self) -> None:
        """A value the codec cannot serialize must surface as ``AssertionError``, not ``TypeError``."""
        offending = cast("JsonValue", {1, 2, 3})
        self.raises(
            AssertionError,
            "require_encodable given a set, which json.dumps cannot serialize",
            lambda: require_encodable("extract_strings", offending),
        )

    def test_the_assertion_error_names_the_operation_and_the_offending_type(self) -> None:
        """The raised message must attribute the failure to the operation and the value's real type."""
        offending = cast("JsonValue", object())
        message = self.refusal(
            AssertionError,
            "require_encodable given a bare object, which json.dumps cannot serialize",
            lambda: require_encodable("content_classification", offending),
        )
        self.contains("content_classification", message, "the operation name in the failure message")
        self.contains("object", message, "the offending value's type name in the failure message")

    def test_the_underlying_type_error_is_chained_not_discarded(self) -> None:
        """The original ``TypeError`` from ``json.dumps`` must still be reachable via exception chaining."""
        offending = cast("JsonValue", {1, 2, 3})
        try:
            require_encodable("digram_matrix", offending)
        except AssertionError as exc:
            self.equal(type(exc.__cause__).__name__, "TypeError", "the chained cause of the assertion")
        else:
            self.fail("require_encodable did not raise for an unencodable value")


if __name__ == "__main__":
    unittest.main()
