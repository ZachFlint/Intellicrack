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

from intellicrack.ui.app import MainWindow

MainWindow.closeEvent
MainWindow._model_browse_worker

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

# ===========================================================================
# 8. Test-only API (called from tests/ but not production code)
# ===========================================================================

from intellicrack.ui.resources.font_manager import FontManager as _FM

_FM.get_code_font_bold
_FM.get_ui_font_bold
_FM.get_heading_font
_FM.get_font_info

from intellicrack.ui.resources.font_manager import DEFAULT_UI_FONT

DEFAULT_UI_FONT

from intellicrack.ui.resources.icon_manager import IconManager as _IM

_IM.get_status_icon
_IM.get_status_pixmap
_IM.preload_icons
_IM.icon_exists

from intellicrack.ui.resources.resource_helper import get_font_path, get_style_path, resource_exists

get_font_path
get_style_path
resource_exists

from intellicrack.credentials.env_loader import CredentialLoader

CredentialLoader.reload
CredentialLoader.list_configured_providers
CredentialLoader.list_missing_providers

_LTP.get_device_info
_LTP.unload_model

from intellicrack.core.process_manager import ProcessManager

ProcessManager.get_all_tracked
ProcessManager.get_running_processes

from intellicrack.providers.model_loader import ModelCache

ModelCache.get_memory_usage
ModelCache.remove

# ===========================================================================
# 9. Exported via __init__.py (vulture doesn't follow re-exports)
# ===========================================================================

from intellicrack.ui.sandbox_config import SandboxMonitorWidget

SandboxMonitorWidget

from intellicrack.providers.model_loader import set_global_cache_size

set_global_cache_size

from intellicrack.providers.xpu_utils import get_optimal_dtype_for_xpu

get_optimal_dtype_for_xpu

from intellicrack.providers.registry import get_provider_registry

get_provider_registry

from intellicrack.ui.panels.stack_viewer import StackDataSource

StackDataSource

# ===========================================================================
# 12. TypedDict / Enum classes (used as structural type contracts)
# ===========================================================================

from intellicrack.providers.openai import OpenAIMessage, OpenAIMessageContent

OpenAIMessage
OpenAIMessageContent

from intellicrack.providers.grok import GrokMessage, GrokMessageContent

GrokMessage
GrokMessageContent

from intellicrack.credentials.oauth import OAuthFlowType

OAuthFlowType
OAuthFlowType.AUTHORIZATION_CODE

# ===========================================================================
# 13. Public API extension points (designed for external callers)
# ===========================================================================

from intellicrack.bridges.schemas import (
    build_schema_parameters,
    get_all_schemas_for_provider,
    validate_and_convert,
)

build_schema_parameters
get_all_schemas_for_provider
validate_and_convert

from intellicrack.bridges.named_pipe_client import NamedPipeClient

NamedPipeClient.set_event_handler

from intellicrack.bridges.installer import ToolInstaller

ToolInstaller.get_all_tool_status

from intellicrack.core.orchestrator import Orchestrator

Orchestrator.get_available_tool_names
Orchestrator.get_current_licensing_analysis
Orchestrator.get_typed_bridge
Orchestrator.activate_binary_by_name

from intellicrack.core.session import SessionManager

SessionManager.export_current

from intellicrack.providers.discovery import ModelDiscovery

ModelDiscovery.discover_all
ModelDiscovery.discover_provider
ModelDiscovery.get_by_id
ModelDiscovery.get_discovery_events
ModelDiscovery.get_last_event
ModelDiscovery.save_cache
ModelDiscovery.load_cache

from intellicrack.providers.ollama import OllamaProvider

OllamaProvider.pull_model

from intellicrack.providers.openrouter import OpenRouterProvider

OpenRouterProvider.get_generation

from intellicrack.credentials.store import CredentialStore

CredentialStore.list_providers
CredentialStore.migrate_from_env
CredentialStore.get_source

from intellicrack.credentials.oauth import OAuthManager, authorize_google

OAuthManager.revoke_token
OAuthManager.to_provider_credentials
authorize_google

from intellicrack.credentials.env_loader import create_env_template

create_env_template

from intellicrack.sandbox.qemu import QMPClient, GuestAgentClient, QEMUSandbox

QMPClient.cont
GuestAgentClient.get_pending_messages
QEMUSandbox.list_snapshots
QEMUSandbox.delete_snapshot

from intellicrack.sandbox.manager import SandboxManager

SandboxManager.cleanup_stale

from intellicrack.ui.sandbox_config import SandboxConfigDialog

SandboxConfigDialog.is_sandbox_available

from intellicrack.ui.panels.stack_viewer import StackViewerPanel

StackViewerPanel.add_source

# ===========================================================================
# 14. ToolOutputPanel delegator methods (called from app.py/orchestrator)
# ===========================================================================

from intellicrack.ui.tools import ToolOutputPanel as _TOP

_TOP.get_bridge_for_tool
_TOP.get_active_process_pid
_TOP.display_analysis_result
_TOP.clear_analysis_tab
_TOP.get_active_tool_widget
_TOP.log_frida_message
_TOP.add_frida_hook_entry
_TOP.get_sandbox_backend
_TOP.load_sandbox_report
_TOP.get_script_panel_state
_TOP.get_code_highlighter
_TOP.wire_stack_viewer_bridges
_TOP.wire_sandbox_backend
_TOP.wire_script_backend

# ===========================================================================
# 15. ScriptGenerator class and ScriptManager methods
# ===========================================================================

from intellicrack.core.script_gen import ScriptGenerator, ScriptManager as _SM

ScriptGenerator

_SM.ensure_script_saved
_SM.reload_script
_SM.record_execution

from intellicrack.core.script_gen import Script as _Script

_Script.add_execution_result

# ===========================================================================
# 16. RegisterState methods (used by x64dbg/debugger bridge tools)
# ===========================================================================

RegisterState.get_gpr_dict
RegisterState.get_segment_registers

# ===========================================================================
# 17. Instance attributes stored for reference / GC prevention
# ===========================================================================

MainWindow._script_manager
MainWindow._script_validator
MainWindow._model_discovery

# ===========================================================================
# 18. Code display accessor (public API for CodeDisplay widget)
# ===========================================================================

from intellicrack.ui.tools import CodeDisplay

CodeDisplay.get_highlighter
