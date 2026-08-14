# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""An out-of-range integer argument is a client mistake, not a server fault.

``codec.py`` accepts any Python integer for an ``int`` parameter without range
checking, and hands it straight to the compiled extension, whose Rust-side
parameters are typed ``usize``/``u64``. PyO3 rejects a negative or oversized
value by raising ``OverflowError``, a subclass of ``ArithmeticError``. This
module insists that failure is classified as a ``400`` the caller can act on,
both directly against :func:`~hexbench.dispatch.translate_exception` and
end-to-end against the real engine through a negative ``write_bytes`` offset.
"""

from __future__ import annotations

import unittest
from typing import Final

from hexbench.dispatch import translate_exception
from hexbench.tests._support import Assertions, HexbenchTestCase


_STATUS_BAD_REQUEST: Final = 400
_VALUE_KIND: Final = "value"


class TranslateOverflowErrorTests(Assertions, unittest.TestCase):
    """``translate_exception`` on a synthetic ``OverflowError``."""

    def test_overflow_error_is_classified_as_a_bad_request(self) -> None:
        """An ``OverflowError`` must translate to a client ``value`` error, not a server fault."""
        translated = translate_exception(OverflowError("can't convert negative int to unsigned"))
        self.equal(translated.kind, _VALUE_KIND, "translated.kind")
        self.equal(translated.status, _STATUS_BAD_REQUEST, "translated.status")


class NegativeOffsetEndToEndTests(HexbenchTestCase):
    """A negative offset reaching the real compiled extension through ``write_bytes``."""

    def test_negative_write_offset_raises_overflow_that_translates_to_bad_request(self) -> None:
        """``write_bytes`` with a negative offset must classify as a 400, not a 500.

        ``codec._decode_int`` performs no range validation, so ``-1`` reaches
        the PyO3-bound ``write_bytes(offset: usize, ...)`` unchanged, which
        raises ``OverflowError`` while converting it to an unsigned Rust
        integer. Left unclassified, that exception falls through
        ``dispatch.translate_exception`` to the ``internal``/``500`` default.
        """
        info = self.session.open_bytes(b"\x00" * 8)
        try:
            self.session.call("write_bytes", {"offset": -1, "data": "00"}, handle=info.handle)
        except OverflowError as exc:
            translated = translate_exception(exc)
        else:
            self.fail("write_bytes(offset=-1, ...) did not raise OverflowError from the compiled extension")
        self.equal(translated.kind, _VALUE_KIND, "translated.kind")
        self.equal(translated.status, _STATUS_BAD_REQUEST, "translated.status")


if __name__ == "__main__":
    unittest.main()
