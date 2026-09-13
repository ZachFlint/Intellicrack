# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""A refusal the caller can act on carries the action, not just the complaint.

``DispatchError`` is the one shape every classified failure reaches a client in,
and the browser renders it as a banner of two lines: the message, and an
optional second line naming what to do next. Only the failures that have a next
step to offer carry that second line, which makes both halves worth insisting
on - a missing detail leaves the banner as unhelpful as it was, and a detail on
every failure makes the line noise nobody reads.
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING, Final

from hexbench.dispatch import DispatchError, operation_for, translate_exception
from hexbench.tests._support import Assertions, HexbenchTestCase, error_of, json_object, wait_for_job


if TYPE_CHECKING:
    from collections.abc import Callable

    from hexbench.codec import JsonValue


_STATUS_BAD_REQUEST: Final = 400
_STATUS_INTERNAL: Final = 500
_UNKNOWN_OPERATION: Final = "not_an_operation_any_engine_publishes"
_CATALOG_ROUTE: Final = "/api/catalog"
_DOCUMENTS_ROUTE: Final = "/api/documents"
_DETAIL_KEY: Final = "detail"


def raised_by(action: Callable[[], object]) -> DispatchError:
    """Run an action that must fail, and hand back the failure it raised.

    Args:
        action: Zero-argument callable expected to raise ``DispatchError``.

    Returns:
        DispatchError: The failure the action raised.

    Raises:
        AssertionError: If the action did not raise ``DispatchError``.
    """
    try:
        action()
    except DispatchError as exc:
        return exc
    message = "the action was expected to raise DispatchError and did not"
    raise AssertionError(message)


class DispatchErrorDetailTests(Assertions, unittest.TestCase):
    """The optional second line, where it is set and where it is not."""

    def test_an_unknown_operation_names_where_the_operations_are_listed(self) -> None:
        """The failure a mistyped operation produces must say where the real names are."""
        raised = raised_by(lambda: operation_for(_UNKNOWN_OPERATION))
        self.equal(raised.kind, "unknown_operation", "raised.kind")
        self.require(raised.detail is not None, "an unknown operation must offer the route that lists the real ones")
        detail = raised.detail or ""
        self.contains("/api/catalog", detail, "raised.detail")
        self.unequal(detail, str(raised), "raised.detail")

    def test_a_failure_with_nothing_to_add_carries_no_detail(self) -> None:
        """A detail is optional, so a banner is not given an empty second line."""
        plain = DispatchError("offset is negative", kind="value", status=_STATUS_BAD_REQUEST)
        self.is_none(plain.detail, "plain.detail")

    def test_translation_preserves_a_detail_that_was_already_set(self) -> None:
        """``translate_exception`` returns a ``DispatchError`` unchanged, detail included."""
        original = DispatchError(
            "the catalogue and the engine have diverged",
            kind="internal",
            status=_STATUS_INTERNAL,
            detail="rebuild the engine",
        )
        translated = translate_exception(original)
        self.equal(translated.detail, "rebuild the engine", "translated.detail")

    def test_a_classified_exception_carries_no_invented_detail(self) -> None:
        """An exception classified by type has nothing to add, and must not pretend otherwise."""
        translated = translate_exception(ValueError("offset is negative"))
        self.equal(translated.kind, "value", "translated.kind")
        self.is_none(translated.detail, "translated.detail")


class ErrorEnvelopeDetailTests(HexbenchTestCase):
    """The detail must survive the HTTP boundary, not just the ``DispatchError``.

    ``DispatchError.detail`` carries the actionable second line the browser's
    ``renderError`` draws under the message, and the design system documents that
    line as coming from it. The synchronous ``/api/op`` route, the asynchronous
    job record and every other producer of the error envelope must therefore put
    a set detail into the JSON, and must leave it out when there is none.
    """

    def test_unknown_operation_response_carries_its_detail(self) -> None:
        """A mistyped operation's 404 body must name the route that lists the real names."""
        response = self.session.post_operation(_UNKNOWN_OPERATION)
        error = error_of(response)
        detail = error.get(_DETAIL_KEY)
        self.require(isinstance(detail, str), "the unknown-operation envelope must carry a string detail")
        self.contains(_CATALOG_ROUTE, detail if isinstance(detail, str) else "", "error.detail")

    def test_missing_document_response_carries_its_detail(self) -> None:
        """A document operation with no handle must tell the caller to open one first."""
        response = self.session.post_operation("write_bytes", {"offset": 0, "data": "00"})
        error = error_of(response)
        detail = error.get(_DETAIL_KEY)
        self.require(isinstance(detail, str), "the missing-document envelope must carry a string detail")
        self.contains(_DOCUMENTS_ROUTE, detail if isinstance(detail, str) else "", "error.detail")

    def test_a_plain_value_failure_response_carries_no_detail(self) -> None:
        """A failure classified only by type must not grow an empty detail line in the body."""
        info = self.session.open_bytes(b"\x00" * 8)
        response = self.session.post_operation("write_bytes", {"offset": -1, "data": "00"}, handle=info.handle)
        error = error_of(response)
        self.equal(error.get("kind"), "value", "error.kind")
        self.require(_DETAIL_KEY not in error, "a type-classified failure must send no detail key at all")

    def test_async_job_error_record_carries_its_detail(self) -> None:
        """A background job that fails with a detail-bearing error must keep the detail in its record."""
        submitted = json_object(self.session.post_operation("write_bytes", {"offset": 0, "data": "00"}, query={"mode": "async"}))
        job_id = submitted.get("job_id")
        self.require(isinstance(job_id, str), "an async submission must return a job id")
        record = wait_for_job(self.session, job_id if isinstance(job_id, str) else "")
        self.equal(record.get("state"), "failed", "record.state")
        error = record.get("error")
        self.require(isinstance(error, dict), "a failed job must carry an error object")
        detail: JsonValue = error.get(_DETAIL_KEY) if isinstance(error, dict) else None
        self.require(isinstance(detail, str), "the async missing-document job error must carry a string detail")
        self.contains(_DOCUMENTS_ROUTE, detail if isinstance(detail, str) else "", "job error.detail")


if __name__ == "__main__":
    unittest.main()
