"""Vulture whitelist for confirmed false positives.

This file is scanned by vulture alongside the source code.
Names referenced here are treated as 'used' to suppress false positive reports.

Usage:
    pixi run vulture src/intellicrack/ vulture_whitelist.py --min-confidence 60
"""

# Sentinel object for attribute-name references that vulture can detect
_wl = type("_wl", (), {})()

# ===========================================================================
# 1. TypedDict fields (accessed via dict key at runtime)
# ===========================================================================

# sandbox/base.py
_wl.old_path
_wl.value_name
_wl.value_data
_wl.direction
_wl.local_address
_wl.local_port
_wl.remote_address
_wl.remote_port
_wl.bytes_sent
_wl.bytes_received

# providers/base.py, bridges/schemas.py
_wl.input_schema
_wl.tool_call_id

# ===========================================================================
# 2. Dataclass fields (used via constructor / dict conversion / serialization)
# ===========================================================================

from intellicrack.sandbox.base import SandboxConfig, SandboxState

SandboxConfig.environment_variables
SandboxState.started_at

from intellicrack.bridges.base import BridgeState, MemorySearchResult, StackFrame

MemorySearchResult.matched_bytes
StackFrame.frame_pointer
StackFrame.stack_pointer
BridgeState.binary_loaded

from intellicrack.core.process_manager import ProcessType, TrackedProcess

ProcessType.ASYNC_SUBPROCESS
TrackedProcess.registered_at

from intellicrack.core.types import RegisterState

RegisterState.rflags

from intellicrack.sandbox.qemu import GuestOS, QEMUSandbox

GuestOS.LINUX
QEMUSandbox.GUEST_SHARED_PATH_WINDOWS
QEMUSandbox.GUEST_SHARED_PATH_LINUX

from intellicrack.ui.panels.stack_viewer import StackFrame as _SVStackFrame

_SVStackFrame.frame_pointer
_SVStackFrame.stack_pointer

from intellicrack.providers.discovery import DiscoveryEvent

DiscoveryEvent.new_models
DiscoveryEvent.removed_models

from intellicrack.providers.model_loader import ModelLoadConfig

ModelLoadConfig.use_flash_attention
ModelLoadConfig.quantization_config

# ===========================================================================
# 3. Provider lifecycle attributes (_credentials / _api_token)
#    Set in connect(), cleared in disconnect().
# ===========================================================================

from intellicrack.providers.base import LLMProviderBase

LLMProviderBase._credentials

from intellicrack.providers.anthropic import AnthropicProvider

AnthropicProvider._credentials

from intellicrack.providers.openai import OpenAIProvider

OpenAIProvider._credentials

from intellicrack.providers.grok import GrokProvider as _GP

_GP._credentials

from intellicrack.providers.huggingface import HuggingFaceProvider

HuggingFaceProvider._credentials
HuggingFaceProvider._api_token

from intellicrack.providers.local_transformers import LocalTransformersProvider as _LTP

_LTP._credentials

from intellicrack.providers.google import GoogleProvider

GoogleProvider._credentials

from intellicrack.providers.ollama import OllamaProvider

OllamaProvider._credentials

from intellicrack.providers.openrouter import OpenRouterProvider

OpenRouterProvider._credentials

# ===========================================================================
# 4. Protocol / dynamic dispatch / library config
# ===========================================================================

# Module-level __getattr__ for lazy imports
__getattr__  # noqa: F821

# Capstone engine md.detail = True
_wl.detail

# sqlite3 conn.row_factory assignment
_wl.row_factory

# Context manager __exit__ protocol parameter
_wl.exc_tb

# Bridge state attributes set dynamically during load_binary / connect
from intellicrack.bridges.binary import BinaryBridge

BinaryBridge.binary_loaded

from intellicrack.bridges.ghidra import GhidraBridge

GhidraBridge._project_path
GhidraBridge.binary_loaded

from intellicrack.bridges.radare2 import Radare2Bridge

Radare2Bridge.binary_loaded

from intellicrack.bridges.x64dbg import X64DbgBridge

X64DbgBridge.binary_loaded

# ===========================================================================
# 5. Qt patterns (dynamic event binding, setattr/getattr cleanup loops)
# ===========================================================================

from intellicrack.ui.app import IntellicrackMainWindow

IntellicrackMainWindow.closeEvent
IntellicrackMainWindow._model_browse_worker

from intellicrack.ui.tools import ToolOutputPanel

ToolOutputPanel._ghidra_bridge
ToolOutputPanel._radare2_bridge

# ===========================================================================
# 6. Import used in cast() at runtime
# ===========================================================================

ToolParam  # noqa: F821

# ===========================================================================
# 7. Attribute set at runtime
# ===========================================================================

from intellicrack.sandbox.windows import WindowsSandbox

WindowsSandbox.started_at

# ===========================================================================
# 10. Bridge methods dispatched via getattr() in ToolRegistry.execute_tool_call
#     All methods below are registered in each bridge's tool_definition property
#     and invoked dynamically: getattr(bridge, function_name, None)
# ===========================================================================

# bridges/binary.py
BinaryBridge.apply_patch
BinaryBridge.revert_patch
BinaryBridge.search_pattern
BinaryBridge.search_pattern_with_wildcards
BinaryBridge.disassemble_at_offset
BinaryBridge.calculate_checksum
BinaryBridge.offset_to_rva
BinaryBridge.get_strings

# bridges/ghidra.py
GhidraBridge.start_headless
GhidraBridge.get_function
GhidraBridge.search_bytes
GhidraBridge.rename_function
GhidraBridge.add_comment
GhidraBridge.get_data_type
GhidraBridge.set_data_type

# bridges/radare2.py
Radare2Bridge.get_function
Radare2Bridge.search_bytes
Radare2Bridge.search_bytes_wildcard
Radare2Bridge.rename_function
Radare2Bridge.add_comment
Radare2Bridge.assemble_at
Radare2Bridge.seek
Radare2Bridge.get_function_address

# bridges/x64dbg.py
X64DbgBridge.set_watchpoint
X64DbgBridge.remove_watchpoint
X64DbgBridge.get_watchpoints
X64DbgBridge.allocate_memory
X64DbgBridge.free_memory
X64DbgBridge.assemble_at
X64DbgBridge.scan_memory
X64DbgBridge._get_process_info

# bridges/frida_bridge.py
from intellicrack.bridges.frida_bridge import FridaBridge

FridaBridge.scan_memory
FridaBridge.enumerate_modules
FridaBridge.enumerate_exports
FridaBridge.get_hooks
FridaBridge.intercept_return
FridaBridge.call_function

# bridges/process.py
from intellicrack.bridges.process import ProcessBridge

ProcessBridge.open_process
ProcessBridge.suspend
ProcessBridge.protect
ProcessBridge.search_pattern
ProcessBridge.inject_dll
ProcessBridge.get_process_info

# bridges/sandbox_bridge.py
from intellicrack.bridges.sandbox_bridge import SandboxBridge

SandboxBridge.copy_to
SandboxBridge.copy_from
SandboxBridge.snapshot_create
SandboxBridge.snapshot_restore

# ===========================================================================
# 11. ToolRegistry typed bridge getters dispatched via getattr() in
#     Orchestrator.get_typed_bridge: getattr(self._tools, getter_name)()
# ===========================================================================

from intellicrack.core.tools import ToolRegistry

ToolRegistry.get_process_bridge
ToolRegistry.get_frida_bridge
ToolRegistry.get_ghidra_bridge
ToolRegistry.get_radare2_bridge
ToolRegistry.get_x64dbg_bridge
ToolRegistry.get_sandbox_bridge
