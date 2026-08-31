# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Pytest fixtures shared by the Ghidra bridge-completeness gate tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast, overload

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.bridges.ghidra import GhidraBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator

_EvalResponder = Callable[[str], object]


@overload
def priv[T](obj: object, name: str, typ: type[T]) -> T: ...
@overload
def priv[T](obj: object, name: str, typ: tuple[type[T], ...]) -> T: ...
def priv(obj: object, name: str, typ: type[object] | tuple[type[object], ...]) -> object:
    """Read a name-mangled-free private attribute off a widget/object with a known type.

    Test modules in this package intentionally reach into panel-private
    widgets (``_labels_table``, ``_kind_combo``, and similar) to drive
    real Qt signal/slot wiring end-to-end. ``getattr`` performs the same
    lookup as direct attribute access without triggering basedpyright's
    ``reportPrivateUsage`` diagnostic, and the explicit ``typ`` argument
    both keeps the result statically typed (instead of falling back to
    ``Any``) and is verified against the live attribute at runtime, so a
    stale/renamed widget type fails loudly here rather than surfacing as
    a confusing ``AttributeError`` deeper in the test body. The overload
    pair mirrors ``isinstance``'s own single-type/tuple-of-types split so
    callers can narrow to one of several acceptable widget types.

    Args:
        obj: The object whose private attribute is being read.
        name: The attribute name to look up.
        typ: The expected type (or tuple of acceptable types) of the
            attribute; checked at runtime and used for the static cast.

    Returns:
        object: The attribute value, cast to ``typ``.

    Raises:
        TypeError: If the attribute's runtime type does not match ``typ``.
    """
    value = getattr(obj, name)
    if not isinstance(value, typ):
        expected = typ.__name__ if isinstance(typ, type) else " | ".join(t.__name__ for t in typ)
        msg = f"{obj!r}.{name} is {type(value).__name__}, expected {expected}"
        raise TypeError(msg)
    return value


def priv_method(obj: object, name: str) -> Callable[[], None]:
    """Read a private zero-argument, no-return bound method off an object.

    Companion to :func:`priv` for the handful of private *methods*
    (e.g. ``_on_remove_bookmark``) these tests invoke directly to drive
    context-menu wiring, where ``type[_T]`` cannot express a callable
    generic alias.

    Args:
        obj: The object whose private method is being looked up.
        name: The method name to look up.

    Returns:
        Callable[[], None]: The bound method, cast to a zero-arg callable.
    """
    return cast("Callable[[], None]", getattr(obj, name))


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process; this
    fixture creates one for the entire session and yields it so every
    widget-construction test in this package can run without re-creating
    (or conflicting on) the singleton application instance.

    Yields:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class FakeGhidraBridge:
    """In-process double for the ``ghidra_bridge`` RPC client.

    Records every call to ``remote_exec``/``remote_eval`` so tests can
    inspect the Jython wire framing emitted by the production
    ``GhidraBridge`` methods. ``eval_response`` supplies the canned
    Ghidra-side return value that ``_execute_remote`` delivers back to
    the production method body under test. This is the only test double
    in this package, and it stands in solely for the external Ghidra
    RPC transport (a genuine boundary that cannot run headless Ghidra in
    the sandbox) -- every bridge method under test still executes for
    real against this fake wire.
    """

    def __init__(self) -> None:
        """Initialise empty call traces and default response values."""
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = None
        self.exec_response: object = None
        self._eval_responder: _EvalResponder | None = None
        self.exec_raises: BaseException | None = None
        self.eval_raises: BaseException | None = None

    def set_eval_responder(self, responder: _EvalResponder) -> None:
        """Install a callable that computes the eval response from the expression.

        Args:
            responder: Callable receiving the expression string and
                returning the desired response value.
        """
        self._eval_responder = responder

    def remote_exec(self, code: str) -> object:
        """Record the script payload and optionally raise or return exec_response.

        Args:
            code: Jython source string emitted by the production bridge.

        Returns:
            object: exec_response when set, otherwise None.

        Raises:
            exc: Re-raised when the caller has set exec_raises on the fake.
        """
        self.exec_calls.append(code)
        exc = self.exec_raises
        if exc is not None:
            raise exc
        return self.exec_response

    def remote_eval(self, expression: str, **_kwargs: object) -> object:
        """Record the expression and return the programmed eval_response.

        Args:
            expression: Sentinel variable name produced by
                ``prepare_remote_script``, or a direct eval expression
                from ``_execute_remote_eval``.
            **_kwargs: Extra keyword arguments accepted to match the
                real ``jfx_bridge`` signature; ignored by the fake.

        Returns:
            object: The responder's return value when one is installed,
            otherwise the static ``eval_response`` field.

        Raises:
            exc: Re-raised when the caller has set eval_raises on the fake.
        """
        self.eval_calls.append(expression)
        exc = self.eval_raises
        if exc is not None:
            raise exc
        if self._eval_responder is not None:
            return self._eval_responder(expression)
        return self.eval_response


@pytest.fixture
def fake() -> FakeGhidraBridge:
    """Provide a fresh FakeGhidraBridge with empty traces.

    Returns:
        FakeGhidraBridge: A test double with empty call lists.
    """
    return FakeGhidraBridge()


@pytest.fixture
def connected_bridge(fake: FakeGhidraBridge) -> GhidraBridge:
    """Provide a GhidraBridge wired to the FakeGhidraBridge, marked ready.

    Args:
        fake: The recording fake fixture.

    Returns:
        GhidraBridge: A bridge instance whose ``_bridge`` attribute is
        the fake and whose ``state`` reports connected and running.
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", fake)
    bridge.state.connected = True
    bridge.state.tool_running = True
    return bridge


def run_async(coro: Coroutine[Any, Any, object]) -> object:
    """Run an async coroutine to completion in a fresh event loop.

    Args:
        coro: Coroutine to execute.

    Returns:
        object: The coroutine's return value.
    """
    return asyncio.run(coro)
