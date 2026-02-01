from collections.abc import Sequence
from typing import Any

from . import _frida as _frida
from . import core as core

__version__: str

Relay = _frida.Relay
FileMonitor = _frida.FileMonitor

ServerNotRunningError = _frida.ServerNotRunningError
ExecutableNotFoundError = _frida.ExecutableNotFoundError
ExecutableNotSupportedError = _frida.ExecutableNotSupportedError
ProcessNotFoundError = _frida.ProcessNotFoundError
ProcessNotRespondingError = _frida.ProcessNotRespondingError
InvalidArgumentError = _frida.InvalidArgumentError
InvalidOperationError = _frida.InvalidOperationError
PermissionDeniedError = _frida.PermissionDeniedError
AddressInUseError = _frida.AddressInUseError
TimedOutError = _frida.TimedOutError
NotSupportedError = _frida.NotSupportedError
ProtocolError = _frida.ProtocolError
TransportError = _frida.TransportError
OperationCancelledError = _frida.OperationCancelledError

def get_device_manager() -> core.DeviceManager: ...
def get_local_device() -> core.Device: ...
def get_remote_device() -> core.Device: ...
def get_usb_device(timeout: int = ...) -> core.Device: ...
def get_device(id: str | None, timeout: int = ...) -> core.Device: ...
def enumerate_devices() -> list[core.Device]: ...
def spawn(
    program: str | Sequence[str | bytes],
    argv: Sequence[str | bytes] | None = ...,
    envp: dict[str, str] | None = ...,
    env: dict[str, str] | None = ...,
    cwd: str | None = ...,
    stdio: str | None = ...,
    **kwargs: Any,
) -> int: ...
def resume(target: int | str) -> None: ...
def kill(target: int | str) -> None: ...
def attach(
    target: int | str,
    realm: str | None = ...,
    persist_timeout: int | None = ...,
) -> core.Session: ...
def inject_library_file(target: int | str, path: str, entrypoint: str, data: str) -> int: ...
def inject_library_blob(target: int | str, blob: bytes, entrypoint: str, data: str) -> int: ...
def query_system_parameters() -> dict[str, Any]: ...
def shutdown() -> None: ...

PortalService = core.PortalService
EndpointParameters = core.EndpointParameters
Compiler = core.Compiler
PackageManager = core.PackageManager
Cancellable = core.Cancellable
