# F20 — Add pre-call logs around external operations (subprocess / network / file I/O)

## Fix description

Per §2.3, every external call must be logged before AND after. Many call sites only log the failure or only log success — not both. This file lists the **pre-call** logs that need to be added.

(Win32/ctypes pre-call logs are in F23. OAuth HTTP probes are in F22. Bridge invocations are in F03.)

## Subprocess pre-call logs

### `src/intellicrack/bridges/installer.py`

| Line | Context | Suggested log |
|-----:|---------|---------------|
| 731 | `_probe_python_package` `await process_manager.run_tracked_async([...], name=f"{tool_info.name.value}-version-probe", ...)` | `_logger.debug("python_package_probe_starting", tool=tool_info.display_name, cmd=cmd)` |
| 823 | `get_version` `await process_manager.run_tracked_async([...], name=f"{tool.value}-version", ...)` | `_logger.debug("tool_version_probe_starting", tool=str(tool), cmd=cmd)` |
| 1147-1151 | `_install_frida` pip-install — success log exists at L1144 (`frida_pip_installing`) but failure-return at L1153-1158 has no log | Add `_logger.warning("frida_pip_install_failed", returncode=result.returncode, stderr=result.stderr.strip())` before each failure return |
| 1161-1165 | `_install_frida` version-verify subprocess | `_logger.debug("frida_version_verify_starting")` before, `.warning` on each failure return |

### `src/intellicrack/sandbox/qemu.py`

| Line | Context | Suggested log |
|-----:|---------|---------------|
| 1044-1059 | `_subprocess_run([pwsh, ...])` for WHPX probe | `_logger.debug("whpx_feature_probe_started", argv=[...])` |
| 1073-1079 | `_subprocess_run([bcdedit, ...])` | `_logger.debug("bcdedit_probe_started", argv=[...])` |

### `src/intellicrack/sandbox/windows.py`

| Line | Context | Suggested log |
|-----:|---------|---------------|
| 1605-1607 | `pktmon start` via `run_command` | `_logger.info("pcap_capture_start_requested", capture_id=capture_id)` |
| 1640 | `pktmon stop` via `run_command` | `_logger.info("pcap_capture_stop_requested")` |
| 1651 | `pktmon etl2pcap` conversion | `_logger.info("pcap_conversion_requested")` |
| 1768-1769 | `Rename-Computer` PowerShell | `_logger.info("anti_evasion_technique_started", technique="rename_computer")` |
| 1773-1789 | Multiple anti-evasion commands | Per-technique entry log |
| 1846 | `mofcomp.exe` from `_apply_wmi_hijack` | `_logger.info("mof_compile_started", mof_path=mof_guest_path)` |
| 2009 | MiniDumpWriteDump PowerShell from `dump_memory` | `_logger.info("guest_minidump_dispatching", target_pid=target_pid, dump_path=sandbox_dump_path)` |
| 2122-2123 | `xcopy` from `extract_dropped_files` | Per-directory `_logger.info("xcopy_started", source=..., dest=...)` |

### `src/intellicrack/ui/tool_config.py`

| Line | Context | Suggested log |
|-----:|---------|---------------|
| 189-251 | `ToolInstallWorker._install_tool` — `httpx.Client.stream(...)` download + `zipfile.extractall` | `_logger.info("tool_download_started", tool_id=self._tool_id, url=url)` before stream; `_logger.info("tool_archive_extracting", tool_id=..., archive=str(zip_path), target=str(self._install_path))` before extractall; `_logger.info("tool_install_completed", tool_id=..., name=name)` after |
| 189 | `self._install_path.mkdir(...)` | Log before/after |
| 213-216 | `zip_path.open("wb")` zip write | Add log |
| 246-249 | Post-install dispatch | Add `_logger.info("post_install_dispatching", tool_id=..., method=...)` |
| 420-425 | `process_manager.run_tracked([sys.executable, '-m', 'pip', 'install', 'ghidra_bridge'], ...)` | `_logger.info("pip_install_started", package="ghidra_bridge")` |
| 430-435 | `process_manager.run_tracked([sys.executable, "-m", "ghidra_bridge.install_server", str(ghidra_root)], ...)` | `_logger.info("ghidra_bridge_server_install_started", ghidra_root=str(ghidra_root))` |
| 732-740 | `process_manager.run_tracked(["cutter", "--version"], ...)` | `_logger.debug("cutter_version_probe_started")` |
| 1056-1066 | `_load_from_config` reads tool settings JSON | `_logger.debug("tool_settings_load_started", tool_id=..., path=...)`; success log on completion |
| 1077-1094 | `_check_status` worker dispatch | `_logger.debug("tool_status_check_requested", tool_id=self._tool_id)` |
| 1114-1156 | `_install_tool` worker dispatch | `_logger.info("tool_install_requested", tool_id=..., install_path=str(install_path))` |
| 1187-1211 | `save_settings` JSON dump | `_logger.info("tool_settings_saved", tool_id=..., path=str(self._config_path))` after `json.dump` |

### `src/intellicrack/ui/sandbox_config.py`

| Line | Context | Suggested log |
|-----:|---------|---------------|
| 117-134 | `SandboxTestWorker.run` — `NamedTemporaryFile` + `Popen([WindowsSandbox.exe, ...])` | `_logger.info("sandbox_wsb_written", path=str(self._wsb_file), size=len(wsb_content))` before; `_logger.info("windows_sandbox_launched", pid=self._process.pid)` after Popen |
| 137-142 | `process_manager.register(...)` | Log registration |
| 148-153 | `self._process.wait(timeout=10)` nonzero exit | `_logger.warning("sandbox_test_nonzero_exit", returncode=..., stderr=...)` |
| 195-205 | Finally-block `ProcessManager.terminate_tree(pid, ...)` | `_logger.info("sandbox_test_process_terminated", pid=pid)` after termination |
| 249-265 | `stop()` — `terminate()` + `kill()` + unregister | `_logger.info("sandbox_test_stop_requested", pid=pid)` on entry |
| 431-441 | `_check_availability` PowerShell subprocess | `_logger.debug("sandbox_availability_check_started")` before |
| 534-566 | `_load_settings` reads sandbox.json | Add entry log; entry+exit symmetric |
| 738-766 | `_apply_config_to_manager` workflow | Add entry log |
| 977-1016 | `_stop_sandbox` `asyncio.run(self._manager.destroy_all())` or `taskkill` | `_logger.info("sandbox_stop_started", method=...)` + success log after |
| 1018-1043 | `_terminate_sandbox_by_name` `process_manager.run_tracked(["taskkill", ...])` | `_logger.info("sandbox_terminate_by_name_started")` |

## Network / HTTP pre-call logs

### `src/intellicrack/credentials/env_loader.py` — file I/O on credential files

(Per §2.3, file writes need surrounding error handling AND logs.)

| Line | Context | Fix |
|-----:|---------|-----|
| 360 | `text = self.env_path.read_text(encoding="utf-8")` | Wrap in try/except OSError; add `_logger.debug("env_file_reading", path=...)` before, `.exception("env_file_read_failed", path=...)` in except |
| 588-591 | `with self.env_path.open("r", ...) as f: existing_text = f.read()` inside `save_to_env_file` | Wrap in try/except + log |
| 627-629 | `self.env_path.parent.mkdir(...)` + `self.env_path.open("w", ...)` write | Wrap + log |
| 682-683 | `path.open("w", encoding="utf-8")` + `f.write(template)` in `create_env_template` | Wrap + log |

### `src/intellicrack/providers/local_transformers.py`

| Line | Context | Fix |
|-----:|---------|-----|
| 118-136 | `_fetch_model_config` httpx GET to HuggingFace | `_logger.debug("hf_config_fetch_started", url=url)` before request |
| 424-495 | `list_models()` lacks entry/exit | Add `self._logger.info("local_list_models_started", device=...)` and `.info("local_list_models_complete", count=len(models))` |
| 1420-1435 | `unload_model` lacks entry log | Add `self._logger.info("model_unload_started", model_id=model_id)` |

### `src/intellicrack/providers/ollama.py`

| Line | Context | Fix |
|-----:|---------|-----|
| 485-552 | `generate()` `client.post` unwrapped | Add try/except + entry/exit logs |
| 554-584 | `embeddings()` `client.post` | Same |
| 363-389 | `list_models()` lacks exit summary | Add exit log |
| 391-419, 421-450, 452-483 | `list_tags`, `list_running_models`, `show_model` | Add entry+exit logs |
| 1614-1657 | `pull_model()` `client.stream` | `self._logger.info("ollama_pull_starting", model=actual_model)` before stream |

### `src/intellicrack/providers/discovery.py` and `gpu_pci_resources.py`

| File | Line | Context | Fix |
|------|-----:|---------|-----|
| `gpu_pci_resources.py` | 93-106 | `_Cfgmgr32.__init__` `ctypes.WinDLL(...)` load | (Covered in F23) |
| `gpu_pci_resources.py` | 228-260 | `enumerate_pci_memory_bars()` | Add entry/exit |

## File write / mutation pre-call logs

### `src/intellicrack/ui/session_manager.py`

| Line | Context | Fix |
|-----:|---------|-----|
| 466 | `SESSIONS_DIR.mkdir(...)` | `_logger.debug("session_dir_ensured", path=str(self.SESSIONS_DIR))` after creation |
| 1326 | `_save_session_to_disk` `mkdir` | Same |
| 1326-1331 | Session JSON write — no pre-write intent log | `_logger.debug("session_save_started", session_id=session_id)` before |
| 995 | `session_file.unlink()` | Add success info log after unlink |
| 1054 | `Path(path).open("w", ...)` export | Promote `session_exported` from debug to info |
| 918 | `_load_selected_session` | Promote to info |

### `src/intellicrack/ui/provider_config.py`

| Line | Context | Fix |
|-----:|---------|-----|
| 257-269 | `_load_env_file_vars` 3× `open(env_path, "r")` attempts | Add per-attempt debug + success info |
| 296-303 | `detect_source()` `self._config_path.open("r")` | Add entry log |
| 2537-2575 | `save_settings` `self._config_path.open("w")` | Add entry log |
| 2577-2602 | `_persist_api_key_to_env` writes `.env` | Add entry + success log (credential write per §2.4) |

## Acceptance criteria

- [ ] All listed external-call sites have a pre-call log
- [ ] File writes have both pre-call and success logs
- [ ] Subprocess invocations log argv + outcome
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
