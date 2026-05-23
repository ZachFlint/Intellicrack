# F07 — Flatten `extra={...}` to structlog kwargs in `sandbox/qemu.py`

## Fix description

`sandbox/qemu.py` uses stdlib-logging-style `extra={"k": v, ...}` instead of canonical structlog flat kwargs. With `structlog.stdlib.BoundLogger` (the configured wrapper) the `extra` dict is recorded as a single nested field rather than flattened into the event payload — log filtering / JSON aggregation loses fidelity. `sandbox/windows.py` and `sandbox/manager.py` use flat kwargs correctly.

**Boundary**: the embedded Linux guest-agent Python source string at `qemu.py:L2143-2465` deliberately uses stdlib `logging.basicConfig(...)` + `extra={...}` — this is guest VM code, not Intellicrack runtime, and is **exempt**. Do NOT change `extra={...}` inside that string.

## Fix template

Before:
```python
_logger.debug("file_copied_to_sandbox", extra={"source": str(source), "dest": str(dest)})
```

After:
```python
_logger.debug("file_copied_to_sandbox", source=str(source), dest=str(dest))
```

Just remove the `extra=` wrapper and lift the dict keys to direct kwargs.

## Sites to fix in `src/intellicrack/sandbox/qemu.py`

(All outside the L2143-L2465 guest-agent string)

| Severity | Line | Event |
|----------|-----:|-------|
| MEDIUM | 2476 | `guest_agent_scripts_created` |
| MEDIUM | 2644 | `result_read_failed` |
| MEDIUM | 2656 | `command_timed_out` |
| MEDIUM | 2677 | `sidecar_read_failed` |
| MEDIUM | 2714-2717 | `result_artifact_cleanup_failed` |
| MEDIUM | 2746 | `binary_not_found` |
| MEDIUM | 2780 | `sandbox_execution_timeout` |
| MEDIUM | 2786 | `sandbox_execution_error` |
| MEDIUM | 2914-2920 | `logs_stable_reached` |
| MEDIUM | 2924-2930 | `logs_stable_max_wait_elapsed` |
| MEDIUM | 2949 | `source_file_not_found` |
| MEDIUM | 2957 | `file_copied_to_sandbox` |
| MEDIUM | 2978 | `sandbox_source_file_not_found` |
| MEDIUM | 2985 | `file_copied_from_sandbox` |
| MEDIUM | 3007 | `snapshot_create_failed` |
| MEDIUM | 3010 | `snapshot_created` |
| MEDIUM | 3027 | `snapshot_restore_failed` |
| MEDIUM | 3030 | `snapshot_restored` |
| MEDIUM | 3068 | `snapshot_delete_failed` |
| MEDIUM | 3071 | `snapshot_deleted` |

## Verification

After the changes, this regex should return zero matches outside the guest-agent string (L2143-L2465):

```
rg "_logger\..*extra=\{" src/intellicrack/sandbox/qemu.py
```

## Acceptance criteria

- [ ] All ~20 sites above flattened to direct kwargs
- [ ] No `extra={...}` in `qemu.py` outside the L2143-L2465 string
- [ ] Embedded guest-agent string left untouched (it uses stdlib `logging` deliberately)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] Spot-check: produce a JSON log line and verify keys are flat at top-level event payload, not nested under `extra`
