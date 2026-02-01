"""Structured logging infrastructure for Intellicrack.

This module provides comprehensive structured logging using structlog,
with JSON file output for log aggregation and colored console output
for development. Includes automatic cleanup of old log files on startup.
"""

from __future__ import annotations

import inspect
import logging
import sys
import time
from datetime import UTC, datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import structlog


if TYPE_CHECKING:
    from types import FrameType, TracebackType

    from structlog.types import EventDict, Processor, WrappedLogger


_ERR_INVALID_CONFIG = "expected LogConfig"
_DEFAULT_LOG_DIR = Path("D:/Intellicrack/logs")
_DEFAULT_LOG_FILE = "intellicrack.log"
_CALL_INFO_DEPTH = 2
_COLLECTION_TRUNCATE_SIZE = 10
_STRING_TRUNCATE_SIZE = 200


class ColoredConsoleRenderer:
    """Custom structlog renderer for colored console output.

    Provides human-readable colored output to the console with ANSI
    color codes based on log level.

    Attributes:
        LEVEL_COLORS: Mapping of log level names to ANSI color codes.
        RESET: ANSI reset code.
    """

    LEVEL_COLORS: ClassVar[dict[str, str]] = {
        "debug": "\033[36m",
        "info": "\033[32m",
        "warning": "\033[33m",
        "error": "\033[31m",
        "critical": "\033[35m",
    }
    RESET: ClassVar[str] = "\033[0m"

    def __call__(
        self,
        _logger: WrappedLogger,
        _name: str,
        event_dict: EventDict,
    ) -> str:
        """Render log event with colors.

        Args:
            _logger: The wrapped logger instance (unused, required by interface).
            _name: The name of the wrapped logger method (unused, required by interface).
            event_dict: The event dictionary to render.

        Returns:
            Formatted colored log message string.
        """
        timestamp = event_dict.pop("timestamp", "")
        level = event_dict.pop("level", "info")
        logger_name = event_dict.pop("logger", "")
        event = event_dict.pop("event", "")
        module = event_dict.pop("module", "")
        func = event_dict.pop("function", "")
        lineno = event_dict.pop("line_number", "")

        color = self.LEVEL_COLORS.get(level.lower(), "")
        level_str = level.upper().ljust(8)

        location = ""
        if module and lineno:
            location = f"{module}:{func}:{lineno}" if func else f"{module}:{lineno}"
        elif logger_name:
            location = logger_name

        context_parts: list[str] = []
        for key, value in sorted(event_dict.items()):
            if key.startswith("_"):
                continue
            context_parts.append(f"{key}={value!r}")

        context_str = ""
        if context_parts:
            context_str = " [" + ", ".join(context_parts) + "]"

        return f"{timestamp} | {color}{level_str}{self.RESET} | {location} | {event}{context_str}"


def cleanup_old_logs(log_dir: Path, retention_days: int) -> int:
    """Delete log files older than retention_days on startup.

    Args:
        log_dir: Directory containing log files.
        retention_days: Number of days to retain log files.

    Returns:
        Number of files deleted.
    """
    if not log_dir.exists():
        return 0

    deleted_count = 0
    cutoff_time = datetime.now(UTC) - timedelta(days=retention_days)
    cutoff_timestamp = cutoff_time.timestamp()

    for log_file in log_dir.glob("*.log*"):
        try:
            mtime = log_file.stat().st_mtime
            if mtime < cutoff_timestamp:
                log_file.unlink()
                deleted_count += 1
        except OSError:
            continue

    return deleted_count


def _add_call_info(
    _logger: WrappedLogger,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Add module, function, and line number to event dict.

    Args:
        _logger: The wrapped logger (unused, required by processor interface).
        _method_name: The log method name (unused, required by processor interface).
        event_dict: The event dictionary.

    Returns:
        Updated event dictionary with call info.
    """
    frame: FrameType | None = inspect.currentframe()
    target_depth = 0

    while frame is not None:
        module_name = frame.f_globals.get("__name__", "")
        if not module_name.startswith(("structlog", "logging")) and "logging.py" not in frame.f_code.co_filename:
            target_depth += 1
            if target_depth >= _CALL_INFO_DEPTH:
                event_dict["module"] = frame.f_code.co_filename.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].replace(".py", "")
                event_dict["function"] = frame.f_code.co_name
                event_dict["line_number"] = frame.f_lineno
                break
        frame = frame.f_back

    return event_dict


def _configure_structlog(
    log_level: str,
    log_dir: Path | None,
    file_enabled: bool,
    console_enabled: bool,
    max_file_size_mb: int,
    backup_count: int,
    json_file: bool,
) -> None:
    """Configure structlog with processors and handlers.

    Args:
        log_level: Log level string.
        log_dir: Directory for log files.
        file_enabled: Whether file logging is enabled.
        console_enabled: Whether console logging is enabled.
        max_file_size_mb: Maximum log file size in MB.
        backup_count: Number of backup files to keep.
        json_file: Whether to output JSON to file.
    """
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
        _add_call_info,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    intellicrack_logger = logging.getLogger("intellicrack")
    intellicrack_logger.setLevel(level)
    intellicrack_logger.handlers.clear()
    intellicrack_logger.propagate = True

    if console_enabled:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                ColoredConsoleRenderer(),
            ],
            foreign_pre_chain=shared_processors,
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    if file_enabled and log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / _DEFAULT_LOG_FILE

        max_bytes = max_file_size_mb * 1024 * 1024
        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)

        if json_file:
            file_formatter = structlog.stdlib.ProcessorFormatter(
                processors=[
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
                foreign_pre_chain=shared_processors,
            )
        else:
            file_formatter = structlog.stdlib.ProcessorFormatter(
                processors=[
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.dev.ConsoleRenderer(colors=False),
                ],
                foreign_pre_chain=shared_processors,
            )

        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


class IntellicrackLogger:
    """Application logger with structlog integration.

    This class manages the logging configuration for the entire application,
    providing structured logging with both file-based JSON output and
    colorized console output.

    Attributes:
        name: The logger name.
    """

    DEFAULT_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
    DEFAULT_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

    def __init__(self, name: str = "intellicrack") -> None:
        """Initialize the Intellicrack logger.

        Args:
            name: The name for this logger instance.
        """
        self.name = name
        self._configured = False

    def configure(
        self,
        level: str = "INFO",
        log_dir: Path | None = None,
        file_enabled: bool = True,
        console_enabled: bool = True,
        max_file_size_mb: int = 10,
        backup_count: int = 5,
        retention_days: int = 14,
        json_file: bool = True,
    ) -> None:
        """Configure the logger with structlog handlers.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            log_dir: Directory for log files.
            file_enabled: Whether to enable file logging.
            console_enabled: Whether to enable console logging.
            max_file_size_mb: Maximum log file size in megabytes.
            backup_count: Number of backup files to keep.
            retention_days: Number of days to retain log files.
            json_file: Whether to output JSON to file.
        """
        if log_dir is not None and file_enabled:
            cleanup_old_logs(log_dir, retention_days)

        _configure_structlog(
            log_level=level,
            log_dir=log_dir,
            file_enabled=file_enabled,
            console_enabled=console_enabled,
            max_file_size_mb=max_file_size_mb,
            backup_count=backup_count,
            json_file=json_file,
        )

        self._configured = True

    def get_logger(self, name: str | None = None) -> logging.Logger:
        """Get a standard logging.Logger instance.

        Args:
            name: Optional child logger name. If None, returns the root logger.

        Returns:
            Logger instance for the specified name.
        """
        if name is None:
            return logging.getLogger(self.name)
        return logging.getLogger(f"{self.name}.{name}")


_app_logger: IntellicrackLogger | None = None


def setup_logging(config: object) -> IntellicrackLogger:
    """Set up application logging from configuration.

    Args:
        config: LogConfig instance with logging settings.

    Returns:
        Configured IntellicrackLogger instance.

    Raises:
        TypeError: If config is not a LogConfig instance.
    """
    global _app_logger  # noqa: PLW0603

    from .config import LogConfig as LogConfigType  # noqa: PLC0415

    if not isinstance(config, LogConfigType):
        raise TypeError(_ERR_INVALID_CONFIG)

    log_dir = _DEFAULT_LOG_DIR

    logger = IntellicrackLogger("intellicrack")
    logger.configure(
        level=config.level,
        log_dir=log_dir,
        file_enabled=config.file_enabled,
        console_enabled=config.console_enabled,
        max_file_size_mb=config.max_file_size_mb,
        backup_count=config.backup_count,
        retention_days=config.retention_days,
        json_file=config.json_file,
    )

    _app_logger = logger
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance for a module.

    Args:
        name: Module name for the logger. If None, returns root app logger.

    Returns:
        Logger instance. Falls back to a basic logger if not configured.
    """
    if _app_logger is None:
        fallback = logging.getLogger("intellicrack")
        if not fallback.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            fallback.addHandler(handler)
            fallback.setLevel(logging.INFO)
        if name:
            return fallback.getChild(name)
        return fallback

    return _app_logger.get_logger(name)


def get_structlog_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structlog bound logger for structured logging.

    Args:
        name: Module name for the logger. If None, returns root app logger.

    Returns:
        Structlog BoundLogger instance for structured logging.
    """
    logger_name = f"intellicrack.{name}" if name else "intellicrack"
    return cast("structlog.stdlib.BoundLogger", structlog.get_logger(logger_name))


def log_exception(
    logger: logging.Logger,
    message: str,
    exc: BaseException,
    level: int = logging.ERROR,
) -> None:
    """Log an exception with full traceback.

    Args:
        logger: Logger instance to use.
        message: Context message for the exception.
        exc: The exception that occurred.
        level: Log level to use.
    """
    logger.log(level, message, extra={"error": str(exc)}, exc_info=True)


def log_tool_call(
    tool_name: str,
    function_name: str,
    arguments: dict[str, object],
    duration_ms: float | None = None,
    success: bool | None = None,
) -> None:
    """Log a tool call for debugging and auditing.

    Args:
        tool_name: Name of the tool being called.
        function_name: Name of the function being invoked.
        arguments: Dictionary of function arguments.
        duration_ms: Optional execution duration in milliseconds.
        success: Optional success indicator.
    """
    slog = get_structlog_logger("tools")
    log_data: dict[str, Any] = {
        "tool": tool_name,
        "function": function_name,
        "arguments": _sanitize_arguments(arguments),
    }
    if duration_ms is not None:
        log_data["duration_ms"] = round(duration_ms, 2)
    if success is not None:
        log_data["success"] = success

    slog.info("tool_call", **log_data)


def _sanitize_arguments(arguments: dict[str, object]) -> dict[str, str]:
    """Sanitize arguments for logging by converting to strings.

    Args:
        arguments: Dictionary of function arguments.

    Returns:
        Dictionary with string representations of arguments.
    """
    sanitized: dict[str, str] = {}
    for key, value in arguments.items():
        if isinstance(value, bytes):
            sanitized[key] = f"<bytes len={len(value)}>"
        elif isinstance(value, list):
            obj_list = cast("list[object]", value)
            if len(obj_list) > _COLLECTION_TRUNCATE_SIZE:
                sanitized[key] = f"<list len={len(obj_list)}>"
            else:
                sanitized[key] = repr(obj_list)
        elif isinstance(value, tuple):
            obj_tuple = cast("tuple[object, ...]", value)
            if len(obj_tuple) > _COLLECTION_TRUNCATE_SIZE:
                sanitized[key] = f"<tuple len={len(obj_tuple)}>"
            else:
                sanitized[key] = repr(obj_tuple)
        elif isinstance(value, dict):
            obj_dict = cast("dict[object, object]", value)
            if len(obj_dict) > _COLLECTION_TRUNCATE_SIZE:
                sanitized[key] = f"<dict len={len(obj_dict)}>"
            else:
                sanitized[key] = repr(obj_dict)
        elif isinstance(value, str) and len(value) > _STRING_TRUNCATE_SIZE:
            sanitized[key] = f"{value[:100]}...({len(value)} chars)"
        else:
            sanitized[key] = repr(value)
    return sanitized


def log_provider_request(
    provider: str,
    model: str,
    messages_count: int,
    tools_count: int,
) -> None:
    """Log an LLM provider request.

    Args:
        provider: Name of the LLM provider.
        model: Model ID being used.
        messages_count: Number of messages in the request.
        tools_count: Number of tools available.
    """
    slog = get_structlog_logger("providers")
    slog.info(
        "llm_request_started",
        provider=provider,
        model=model,
        messages_count=messages_count,
        tools_count=tools_count,
    )


def log_provider_response(
    provider: str,
    model: str,
    tool_calls_count: int,
    duration_ms: float,
    tokens_used: int | None = None,
) -> None:
    """Log an LLM provider response.

    Args:
        provider: Name of the LLM provider.
        model: Model ID that responded.
        tool_calls_count: Number of tool calls in the response.
        duration_ms: Response time in milliseconds.
        tokens_used: Optional number of tokens used.
    """
    slog = get_structlog_logger("providers")
    log_data: dict[str, Any] = {
        "provider": provider,
        "model": model,
        "tool_calls_count": tool_calls_count,
        "duration_ms": round(duration_ms, 2),
    }
    if tokens_used is not None:
        log_data["tokens_used"] = tokens_used

    slog.info("llm_request_complete", **log_data)


def log_binary_operation(
    operation: str,
    path: str | Path,
    **kwargs: object,
) -> None:
    """Log a binary analysis operation.

    Args:
        operation: Type of operation (load, patch, save, etc.).
        path: Path to the binary file.
        **kwargs: Additional operation-specific context.
    """
    slog = get_structlog_logger("binary")
    slog.info(f"binary_{operation}", path=str(path), **kwargs)


def log_sandbox_operation(
    operation: str,
    sandbox_type: str,
    **kwargs: object,
) -> None:
    """Log a sandbox operation.

    Args:
        operation: Type of operation (start, stop, execute, etc.).
        sandbox_type: Type of sandbox (windows, qemu, etc.).
        **kwargs: Additional operation-specific context.
    """
    slog = get_structlog_logger("sandbox")
    slog.info(f"sandbox_{operation}", sandbox_type=sandbox_type, **kwargs)


def log_session_operation(
    operation: str,
    session_id: str | None = None,
    **kwargs: object,
) -> None:
    """Log a session operation.

    Args:
        operation: Type of operation (create, load, save, etc.).
        session_id: Optional session identifier.
        **kwargs: Additional operation-specific context.
    """
    slog = get_structlog_logger("session")
    log_data: dict[str, object] = dict(kwargs)
    if session_id:
        log_data["session_id"] = session_id
    slog.info(f"session_{operation}", **log_data)


def log_analysis_operation(
    operation: str,
    target: str,
    **kwargs: object,
) -> None:
    """Log a license analysis operation.

    Args:
        operation: Type of analysis operation.
        target: Target being analyzed.
        **kwargs: Additional analysis-specific context.
    """
    slog = get_structlog_logger("analysis")
    slog.info(f"analysis_{operation}", target=target, **kwargs)


class OperationTimer:
    """Context manager for timing operations and logging duration.

    Attributes:
        operation: The operation name.
        logger_name: The logger name to use.
        context: Additional context for the log.
    """

    def __init__(
        self,
        operation: str,
        logger_name: str = "operations",
        **context: object,
    ) -> None:
        """Initialize the operation timer.

        Args:
            operation: The operation name.
            logger_name: The logger name to use.
            **context: Additional context for the log.
        """
        self.operation = operation
        self.logger_name = logger_name
        self.context = context
        self._start_time: float = 0.0
        self._slog = get_structlog_logger(logger_name)

    def __enter__(self) -> OperationTimer:
        """Start the timer and log operation start.

        Returns:
            Self for context manager use.
        """
        self._start_time = time.perf_counter()
        self._slog.debug(f"{self.operation}_started", **self.context)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Stop the timer and log operation completion.

        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception value if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.
        """
        duration_ms = (time.perf_counter() - self._start_time) * 1000

        if exc_type is not None:
            self._slog.error(
                f"{self.operation}_failed",
                duration_ms=round(duration_ms, 2),
                error=str(exc_val) if exc_val else str(exc_type),
                **self.context,
            )
        else:
            self._slog.info(
                f"{self.operation}_complete",
                duration_ms=round(duration_ms, 2),
                **self.context,
            )
