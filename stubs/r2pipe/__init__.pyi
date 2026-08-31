"""Type stubs for r2pipe library."""

from typing import Any

class open_sync:
    """Synchronous r2pipe connection."""

    _child: Any

    def cmd(self, command: str) -> str:
        """Execute a command and return the output."""
        ...

    def cmdj(self, command: str) -> Any:
        """Execute a command and return JSON-parsed output."""
        ...

    def quit(self) -> None:
        """Close the r2pipe connection."""
        ...

class open_async:
    """Asynchronous r2pipe connection."""

    _child: Any

    async def cmd(self, command: str) -> str:
        """Execute a command and return the output."""
        ...

    async def cmdj(self, command: str) -> Any:
        """Execute a command and return JSON-parsed output."""
        ...

    async def quit(self) -> None:
        """Close the r2pipe connection."""
        ...

def open(path: str, flags: list[str] | None = None) -> open_sync:
    """Open a new r2pipe connection.

    Args:
        path: Path to binary or '-' for empty session.
        flags: Additional radare2 flags.

    Returns:
        open_sync connection instance.
    """
    ...
