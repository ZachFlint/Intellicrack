"""Test fixtures for 09-intellicrack-domain.yml."""

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


class Orchestrator:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ruleid: intellicrack-logging-i1-tool-dispatch-without-context
    def execute_tool_call(self, tool_name: str, args: dict) -> None:
        result = args

    # ok: intellicrack-logging-i1-tool-dispatch-without-context
    def invoke_tool(self, tool_name: str, args: dict) -> None:
        self._logger.info("tool_invoking", tool_name=tool_name)


def fn_i2_bad_write(address: int, data: bytes) -> None:
    # ruleid: intellicrack-logging-i2-memory-patch-without-audit-log
    WriteProcessMemory(0, address, data, len(data), 0)


def fn_i2_ok(address: int, data: bytes) -> None:
    _logger.info("memory_write_applying", address=hex(address), size=len(data))
    # ok: intellicrack-logging-i2-memory-patch-without-audit-log
    WriteProcessMemory(0, address, data, len(data), 0)


def fn_i3_bad(session) -> None:
    # ruleid: intellicrack-logging-i3-frida-script-load-without-id-log
    script = session.create_script("Interceptor.attach()")


def fn_i3_ok(session) -> None:
    script = session.create_script("Interceptor.attach()")
    # ok: intellicrack-logging-i3-frida-script-load-without-id-log
    _logger.info("frida_script_created", script_id=id(script))


def fn_i4_bad(runner, binary_path: str) -> None:
    # ruleid: intellicrack-logging-i4-disassembler-call-missing-binary-context
    runner.run_ghidra(binary_path)


def fn_i4_ok(runner, binary_path: str) -> None:
    _logger.info("ghidra_starting", binary_path=binary_path)
    # ok: intellicrack-logging-i4-disassembler-call-missing-binary-context
    runner.run_ghidra(binary_path)


class ProviderNoLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ruleid: intellicrack-logging-i5-provider-completion-without-model
    def generate(self, prompt: str) -> str:
        return prompt


class ProviderWithLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ok: intellicrack-logging-i5-provider-completion-without-model
    def generate(self, prompt: str, model: str = "gpt-4o") -> str:
        self._logger.info("provider_generating", model=model)
        return prompt


class CredentialStoreNoLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ruleid: intellicrack-logging-i6-credential-op-missing-key-id
    def save(self, key: str, value: str) -> None:
        pass


class CredentialStoreWithLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ok: intellicrack-logging-i6-credential-op-missing-key-id
    def save(self, key: str, value: str) -> None:
        self._logger.info("credential_saving", key_id=key)


class SessionStateNoLog:
    def do(self, session) -> None:
        # ruleid: intellicrack-logging-i7-session-state-change-without-session-id
        session.active_target = "firefox"


class SessionStateWithLog:
    def do(self, session, session_id: str) -> None:
        _logger.info("session_target_changed", session_id=session_id)
        # ok: intellicrack-logging-i7-session-state-change-without-session-id
        session.active_target = "firefox"


class SandboxNoLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ruleid: intellicrack-logging-i8-sandbox-lifecycle-without-log
    def start(self, config: dict) -> None:
        x = config


class SandboxWithLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ok: intellicrack-logging-i8-sandbox-lifecycle-without-log
    def start(self, config: dict) -> None:
        self._logger.info("sandbox_starting", config_name=config.get("name"))


class UnpackerNoLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ruleid: intellicrack-logging-i9-unpack-without-packer-log
    def unpack(self, binary_path: str) -> None:
        x = binary_path


class UnpackerWithLog:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ok: intellicrack-logging-i9-unpack-without-packer-log
    def unpack(self, binary_path: str) -> None:
        self._logger.info("unpack_started", binary_path=binary_path, packer="UPX")


def WriteProcessMemory(*args, **kwargs) -> None:
    return None
