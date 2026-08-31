# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Qt-signaling logging handler for the Log Viewer.

Bridges the stdlib ``logging`` pipeline (which is fed by structlog via ``ProcessorFormatter``) into a Qt signal so the viewer can react to
live records on the GUI thread.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import TYPE_CHECKING, Final, Self, cast, override

import structlog
from PyQt6 import sip
from PyQt6.QtCore import QObject, pyqtBoundSignal, pyqtSignal

from intellicrack.core.logging import get_logger, get_stdlib_root_logger
from intellicrack.ui.log_viewer._record import LogRecordDict, from_logging_record


if TYPE_CHECKING:
    from structlog.types import Processor


_HANDLER_NAME: Final[str] = "intellicrack.log_viewer.qt"

_logger = get_logger(__name__)


class _HandlerBridge(QObject):
    """Internal :class:`QObject` carrying the ``record_received`` signal.

    The handler can't subclass :class:`QObject` directly without provoking
    metaclass conflicts with :class:`logging.Handler`. This thin wrapper
    keeps the signal definition cleanly separated.

    Attributes:
        record_received: Emitted with a fully formed
            :class:`LogRecordDict` for every record the handler accepts.
    """

    record_received = pyqtSignal(dict)


def _shared_processors() -> list[Processor]:
    """Return the structlog shared-processor chain used by file handlers.

    Mirrors the chain installed in
    :func:`intellicrack.core.logging._configure_structlog` for foreign
    (raw ``logging``) records so they get timestamps, level, and logger
    name before the formatter strips meta keys.

    The frame-walking ``_add_call_info`` processor is intentionally
    omitted because the originating frame is no longer accurate by the
    time the formatter runs on the handler thread; the viewer instead
    reads ``module`` / ``funcName`` / ``lineno`` directly from the
    ``LogRecord`` in :func:`from_logging_record`.

    Returns:
        list[Processor]: Ordered shared processors for the viewer's
            ``ProcessorFormatter``.
    """
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]


class _ReentrancyGuard:
    """Thread-local guard preventing recursive ``emit`` calls.

    Slots connected to ``record_received`` may themselves log, which would otherwise produce unbounded recursion. The guard drops inner
    emissions silently while leaving disk/console logging untouched.
    """

    def __init__(self) -> None:
        """Initialize the guard with a fresh thread-local."""
        self._tls: threading.local = threading.local()

    def is_active(self) -> bool:
        """Return ``True`` when an outer ``emit`` is already in progress.

        Returns:
            bool: ``True`` when a re-entrant emission was detected.
        """
        return bool(getattr(self._tls, "active", False))

    def __enter__(self) -> Self:
        """Mark the current thread as inside an emit.

        Returns:
            Self: For use with :keyword:`with`.
        """
        self._tls.active = True
        return self

    def __exit__(self, *_exc: object) -> None:
        """Clear the active flag on the current thread.

        Args:
            *_exc: Standard ``__exit__`` arguments (unused).
        """
        self._tls.active = False


class QtSignalingHandler(logging.Handler):
    """Logging handler that forwards records into a Qt signal.

    The handler converts each accepted :class:`logging.LogRecord` into a
    :class:`LogRecordDict` on the calling thread, then emits
    ``record_received`` so connected slots can run on the GUI thread via
    a queued connection. The handler is safe to install on the root
    logger alongside the existing console and file handlers.

    Attributes:
        bridge: Internal :class:`QObject` exposing ``record_received``.
        paused: When ``True``, records are accepted but no signal is
            emitted.
    """

    bridge: _HandlerBridge
    paused: bool
    _disabled: bool

    def __init__(self) -> None:
        """Initialize the handler at level ``NOTSET`` with the structlog formatter pre-attached."""
        super().__init__(level=logging.NOTSET)
        self.bridge = _HandlerBridge()
        self.paused = False
        self._disabled = False
        self._guard = _ReentrancyGuard()
        self.set_name(_HANDLER_NAME)
        self.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processors=[structlog.processors.JSONRenderer()],
                foreign_pre_chain=_shared_processors(),
            ),
        )
        _logger.info("qt_signaling_handler_initialized", handler_name=_HANDLER_NAME)

    @property
    def record_received(self) -> pyqtBoundSignal:
        """Expose the bridge's record-received signal.

        Returns:
            pyqtBoundSignal: Bound signal emitted with a
                :class:`LogRecordDict`.
        """
        return self.bridge.record_received

    def set_paused(self, *, paused: bool) -> None:
        """Toggle whether the handler emits to subscribers.

        Args:
            paused: ``True`` suppresses emission; ``False`` resumes it.
        """
        self.paused = paused

    @override
    def emit(self, record: logging.LogRecord) -> None:
        """Convert ``record`` to a dict and emit it on the bridge.

        Re-entrant emissions on the same thread are dropped to avoid
        infinite recursion when a connected slot logs. Emissions are
        skipped silently after the underlying :class:`QObject` bridge has
        been destroyed (typical during application teardown) so the
        logging pipeline does not surface ``RuntimeError`` cascades while
        Qt cleanup is in progress.

        Args:
            record: The standard logging record to forward.
        """
        if self.paused or self._disabled:
            return
        if self._guard.is_active():
            return
        if sip.isdeleted(self.bridge):
            self._disabled = True
            return
        try:
            with self._guard:
                self.format(record)
                payload: LogRecordDict = from_logging_record(record)
                self.bridge.record_received.emit(cast("dict[str, object]", payload))
        except RuntimeError:
            if sip.isdeleted(self.bridge):
                self._disabled = True
            else:
                self.handleError(record)
        except (TypeError, ValueError, AttributeError, OSError):
            self.handleError(record)


class _HandlerState:
    """Container for the shared :class:`QtSignalingHandler` singleton.

    Module-level state is encapsulated in a class so the module avoids
    ``global`` declarations while still providing process-wide
    idempotency for ``install_qt_log_handler``.

    Attributes:
        handler: The currently installed handler, or ``None`` when not
            installed.
    """

    handler: QtSignalingHandler | None = None


_handler_state = _HandlerState()
_handler_state_lock: threading.Lock = threading.Lock()


def install_qt_log_handler() -> QtSignalingHandler:
    """Install (or return the existing) Qt-signaling handler on the root logger.

    The function is idempotent: repeated calls return the same handler
    instance and do not attach duplicate handlers. The handler is
    attached to the **root** logger so it observes records from
    ``intellicrack`` (which propagates) and any third-party libraries.

    Returns:
        QtSignalingHandler: The shared handler instance.
    """
    with _handler_state_lock:
        if _handler_state.handler is None:
            _handler_state.handler = QtSignalingHandler()
        handler = _handler_state.handler
        root = get_stdlib_root_logger()
        if handler not in root.handlers:
            root.addHandler(handler)
        return handler


def uninstall_qt_log_handler() -> None:
    """Detach and forget the shared handler if one is installed.

    Used by tests to keep state clean between cases. Safe to call when no handler has been installed.
    """
    with _handler_state_lock:
        handler = _handler_state.handler
        if handler is None:
            return
        root = get_stdlib_root_logger()
        if handler in root.handlers:
            root.removeHandler(handler)
        _safe_close_handler(handler)
        _handler_state.handler = None


def _safe_close_handler(handler: logging.Handler) -> None:
    """Close a handler, ignoring expected I/O errors during teardown.

    Args:
        handler: The handler to close.
    """
    with contextlib.suppress(OSError, ValueError):
        handler.close()


def get_qt_log_handler() -> QtSignalingHandler | None:
    """Return the currently installed Qt log handler, if any.

    Returns:
        QtSignalingHandler | None: The shared handler instance, or
            ``None`` when not installed.
    """
    return _handler_state.handler
