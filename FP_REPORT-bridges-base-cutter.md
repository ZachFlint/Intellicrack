# False-Positive Report

This unit (semgrep-logging/bridges-base-cutter) targets:

- `src/intellicrack/bridges/base.py`
- `src/intellicrack/bridges/cutter.py`
- `src/intellicrack/bridges/hex_state.py`
- `src/intellicrack/bridges/schemas.py`

All 34 findings in `cutter.py`, both findings in `hex_state.py`, and both findings in `schemas.py` were remediated directly with canonical fixes. The 1 `h3-state-assignment-without-log` finding in `base.py` was also remediated (entry log added to the `BridgeState` setter on `ToolBridgeBase`). The remaining 45 findings are exclusively in `src/intellicrack/bridges/base.py` and arise from two categories of false positives detailed below.

## FP: intellicrack-logging-d6-bridge-method-no-entry-log at src/intellicrack/bridges/base.py (44 findings)

**Semgrep message:** A public method on a Bridge class has no log call at all. Every bridge method crosses the boundary between Intellicrack and an external tool - that boundary is exactly what the unified log stream is supposed to capture. Add at least an entry log: `self._logger.info("bridge_op_started", <context kwargs>)`.

### FP Category 1: dataclass query methods on `BridgeCapabilities` / `BridgeState`

**Affected lines and methods:**
- line 266: `BridgeCapabilities.has_capability`
- line 277: `BridgeCapabilities.supports_arch`
- line 288: `BridgeCapabilities.supports_format`
- line 322: `BridgeState.is_ready`
- line 330: `BridgeState.clear_error`

**Current code (example, line 266-275):**
```python
def has_capability(self, capability: str) -> bool:
    """Check if a specific capability is supported.

    Args:
        capability: Name of the capability to check.

    Returns:
        bool: True if the capability is supported.
    """
    return getattr(self, f"supports_{capability}", False)
```

**Why this is a false positive:** `BridgeCapabilities` and `BridgeState` are `@dataclass` value objects whose names end in `Capabilities` / `State` (matched by the rule's `.*Bridge.*` class-name regex). The flagged methods are pure in-memory query/mutator helpers on these value objects - they do NOT cross any boundary to an external tool. The rule already carves out trivial `return X` getters via the `def $M(self, ...) -> $RT: return $X` pattern-not branch, but that pattern-not does not match because the body contains a Google-style docstring (a string-literal statement) in addition to the return, so Semgrep's pattern-not does not consume the whole method body. Adding an entry log on every `has_capability()` call would flood the log stream with trivial predicate queries that convey no operational information.

**Proposed resolution:** `adjust rule pattern-not` - extend the pattern-not branches of `intellicrack-logging-d6-bridge-method-no-entry-log` in `.semgrep/logging/04-coverage-gaps.yml` to include docstring-plus-return bodies, e.g. `def $M(self, ...) -> $RT: """..."""\n    return $X`. Until the rule is updated, these are recorded as false positives. No code change is appropriate because the dataclass value objects deliberately do not cross any tool boundary.

### FP Category 2: `@abstractmethod` contract declarations on `ToolBridgeBase` and its subclasses

**Affected lines and enclosing classes:**
- lines 400, 414: `ToolBridgeBase` (`initialize`, `is_available`)
- lines 439, 450, 454, 479, 490, 517, 528, 539, 550, 558, 566: `StaticAnalysisBridge`
- lines 622, 642, 674: `DynamicAnalysisBridge`
- lines 697, 701, 705, 709, 717, 725, 733, 762, 770, 778, 798: `DebuggerBridge`
- lines 846, 857, 886, 894, 905, 944: `InstrumentationBridge`
- lines 969, 980, 1001, 1012, 1023, 1034: `BinaryOperationsBridge`

**Current code (example, line 400-407):**
```python
@abstractmethod
async def initialize(self, tool_path: Path | None = None) -> None:
    """Initialize the tool bridge.

    Args:
        tool_path: Optional path to tool installation.
                  If None, will auto-detect or download.
    """
```

**Why this is a false positive:** Every flagged method is declared with `@abstractmethod` and has only a Google-style docstring (no executable body - Python treats the docstring alone as the method body and returns `None`). These methods are CONTRACT DECLARATIONS on the abstract base classes (`ToolBridgeBase`, `StaticAnalysisBridge`, `DynamicAnalysisBridge`, `DebuggerBridge`, `InstrumentationBridge`, `BinaryOperationsBridge`) and do not execute at runtime - concrete subclasses (e.g. `CutterBridge`) override them and are responsible for emitting their own `self._logger.info(...)` entry logs. The d6 rule does not have a pattern-not carve-out for `@abstractmethod`, so it flags every declaration. Adding a log call inside an `@abstractmethod` body would either (a) silently run when a subclass calls `super().method(...)`, creating misleading log events attributed to the base class, or (b) never run because subclasses fully override the method, creating dead code. Concrete implementations in `cutter.py`, `hex_editor.py`, etc. ARE the correct place for entry logs - and this PR has already added them to `cutter.py`.

**Proposed resolution:** `adjust rule pattern-not` - add a pattern-not branch of the form `@abstractmethod\ndef $M(self, ...): ...` (plus `async def` and arbitrary-decorator variants) to `intellicrack-logging-d6-bridge-method-no-entry-log` so that abstract declarations are not treated as concrete methods lacking entry logs. Until the rule is updated, these are recorded as false positives because adding log calls to abstract method bodies would violate the abstract-contract idiom and produce either misleading or unreachable log events.

## FP: intellicrack-logging-i8-sandbox-lifecycle-without-log at src/intellicrack/bridges/base.py:705

**Semgrep message:** Sandbox lifecycle transitions (`start`, `stop`, `reset`, `snapshot`, `restore`, `launch`) must be logged - sandbox execution is one of the most security-sensitive boundaries the platform crosses. Emit entry and result logs.

**Current code (lines 705-707):**
```python
@abstractmethod
async def stop(self) -> None:
    """Stop debugging (terminate process)."""
```

**Why this is a false positive:** This is the same abstract-method FP as FP Category 2 above, specialized to the i8 sandbox-lifecycle rule. `DebuggerBridge.stop` is an `@abstractmethod` DEBUGGER contract (it instructs a concrete debugger like x64dbg to terminate the debuggee process). It is not a sandbox lifecycle method - `DebuggerBridge` is a debugger base class, not a sandbox base class. The rule fires because it matches on the unqualified name `def stop(...)` without checking the enclosing class or decorator. Concrete debugger implementations are responsible for emitting their own lifecycle logs.

**Proposed resolution:** `adjust rule pattern-not` - both (a) add an `@abstractmethod` pattern-not carve-out (shared with the d6 fix above), and (b) narrow `intellicrack-logging-i8-sandbox-lifecycle-without-log`'s class scoping so that it fires only inside classes whose names contain `Sandbox` / `Emulator` rather than on every `def stop(...)` in the codebase.
