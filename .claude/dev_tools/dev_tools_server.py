"""MCP Dev-Tools Server for Intellicrack.

Exposes development tools (linting, testing, building, VCS, security)
to Claude Code agents via the Model Context Protocol.
"""
from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Timer
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import TIMEOUT, WORKING_DIR
from .tools.formatters import register_formatter_tools
from .tools.python_linting import register_python_linting_tools
from .tools.testing import register_testing_tools
from .tools.vcs import register_vcs_tools


mcp = FastMCP("dev-tools")

LOG_FILE = WORKING_DIR / ".claude" / "dev_tools" / "mcp_tool_invocations.log"

MAX_STDOUT_SIZE = 100000
MAX_STDERR_SIZE = 50000
MAX_COMMAND_LOG_ARGS = 10


def _kill_process_tree(proc: subprocess.Popen[str]) -> None:
    """Kill a process and all its children (Windows and POSIX compatible)."""
    if proc.poll() is not None:
        return

    pid = proc.pid
    try:
        import psutil

        with contextlib.suppress(psutil.NoSuchProcess):
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                with contextlib.suppress(psutil.NoSuchProcess):
                    child.kill()
            with contextlib.suppress(psutil.NoSuchProcess):
                parent.kill()
            _, alive = psutil.wait_procs([*children, parent], timeout=3)
            for p in alive:
                with contextlib.suppress(psutil.NoSuchProcess):
                    p.kill()
    except ImportError:
        if sys.platform == "win32":
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=10,
                    check=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
        else:
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        with contextlib.suppress(Exception):
            proc.kill()


def log_tool_invocation(
    tool_name: str,
    args: list[str],
    result: dict[str, Any],
) -> None:
    """Log every MCP tool invocation to a file for verification."""
    with contextlib.suppress(Exception):
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": tool_name,
            "command": args[:MAX_COMMAND_LOG_ARGS] if len(args) > MAX_COMMAND_LOG_ARGS else args,
            "return_code": result.get("return_code", -1),
            "success": result.get("success", False),
            "has_findings": result.get("has_findings", False),
            "stdout_length": len(result.get("stdout", "")),
            "stderr_length": len(result.get("stderr", "")),
        }

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")


_TOOL_NAMES = frozenset({
    "ruff", "mypy", "bandit", "pydocstyle", "pydoclint",
    "pytest", "coverage", "git",
})


def _detect_tool_name(args: list[str]) -> str | None:
    """Detect the tool name from command arguments."""
    for arg in args:
        if arg in _TOOL_NAMES:
            return arg
    return None


def _run_subprocess_with_timeout(
    args: list[str],
    cwd: Path,
    timeout: int,
) -> dict[str, Any]:
    """Execute subprocess with robust timeout handling and process cleanup."""
    popen_kwargs: dict[str, Any] = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "text": True,
    }

    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        popen_kwargs["start_new_session"] = True

    proc: subprocess.Popen[str] | None = None
    timer: Timer | None = None
    timed_out = False

    def timeout_handler() -> None:
        nonlocal timed_out
        timed_out = True
        if proc is not None:
            _kill_process_tree(proc)

    try:
        proc = subprocess.Popen(args, **popen_kwargs)
        timer = Timer(timeout, timeout_handler)
        timer.start()

        try:
            stdout, stderr = proc.communicate()
        except Exception:
            stdout, stderr = "", ""
            if proc.poll() is None:
                _kill_process_tree(proc)

        if timer is not None:
            timer.cancel()

        if timed_out:
            return {
                "success": False,
                "stdout": stdout[:1000] if stdout else "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1,
                "has_findings": False,
            }

        stdout = stdout or ""
        stderr = stderr or ""

        if len(stdout) > MAX_STDOUT_SIZE:
            stdout = stdout[:MAX_STDOUT_SIZE] + "\n... (output truncated)"
        if len(stderr) > MAX_STDERR_SIZE:
            stderr = stderr[:MAX_STDERR_SIZE] + "\n... (output truncated)"

        return {
            "success": proc.returncode in {0, 1},
            "stdout": stdout,
            "stderr": stderr,
            "return_code": proc.returncode,
            "has_findings": proc.returncode == 1,
        }

    except FileNotFoundError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Command not found: {e}",
            "return_code": -1,
            "has_findings": False,
        }
    except PermissionError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Permission denied: {e}",
            "return_code": -1,
            "has_findings": False,
        }
    except OSError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"OS error: {e}",
            "return_code": -1,
            "has_findings": False,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Unexpected error: {type(e).__name__}: {e}",
            "return_code": -1,
            "has_findings": False,
        }
    finally:
        if timer is not None:
            timer.cancel()
        if proc is not None and proc.poll() is None:
            _kill_process_tree(proc)


def run_command(
    args: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    *,
    capture_output: bool = True,
    tool_name: str | None = None,
) -> dict[str, Any]:
    """Execute a subprocess command with proper error handling.

    Args:
        args: Command and arguments to execute.
        cwd: Working directory for the command.
        timeout: Timeout in seconds.
        capture_output: Whether to capture stdout/stderr (ignored, always True).
        tool_name: Optional tool name for logging (auto-detected if not provided).

    Returns:
        Dict with success, stdout, stderr, and return_code.
    """
    del capture_output
    effective_timeout = timeout or TIMEOUT
    effective_cwd = cwd or WORKING_DIR
    detected_tool = tool_name or _detect_tool_name(args)

    output = _run_subprocess_with_timeout(args, effective_cwd, effective_timeout)
    log_tool_invocation(detected_tool or "unknown", args, output)
    return output


def error_result(message: str) -> dict[str, Any]:
    """Create a standardized error result."""
    return {
        "success": False,
        "stdout": "",
        "stderr": message,
        "return_code": -1,
        "has_findings": False,
    }


register_python_linting_tools(mcp, run_command, error_result)
register_formatter_tools(mcp, run_command, error_result)
register_testing_tools(mcp, run_command, error_result)
register_vcs_tools(mcp, run_command, error_result)


if __name__ == "__main__":
    mcp.run()
