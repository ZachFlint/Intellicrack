# Vulture whitelist for Intellicrack false positives.
# Bridge methods dispatched via getattr(), Qt virtual overrides, ctypes _fields_.

intellicrack.__init__.__getattr__  # unused-function
intellicrack.bridges.base.matched_bytes  # unused-variable
intellicrack.bridges.cutter.get_function  # unused-method
intellicrack.bridges.cutter.search_bytes  # unused-method
intellicrack.bridges.cutter.search_bytes_wildcard  # unused-method
intellicrack.bridges.cutter.rename_function  # unused-method
intellicrack.bridges.cutter.add_comment  # unused-method
intellicrack.bridges.cutter.assemble_at  # unused-method
intellicrack.bridges.cutter.seek  # unused-method
intellicrack.bridges.cutter.get_function_address  # unused-method
intellicrack.bridges.frida_bridge.enumerate_modules  # unused-method
intellicrack.bridges.frida_bridge.enumerate_exports  # unused-method
intellicrack.bridges.frida_bridge.get_hooks  # unused-method
intellicrack.bridges.frida_bridge.execute_script  # unused-method
intellicrack.bridges.frida_bridge.intercept_return  # unused-method
intellicrack.bridges.frida_bridge.call_function  # unused-method
intellicrack.bridges.frida_bridge.allocate_memory  # unused-method
intellicrack.bridges.frida_bridge.protect_memory  # unused-method
intellicrack.bridges.frida_bridge.find_base_address  # unused-method
intellicrack.bridges.frida_bridge.resolve_symbol  # unused-method
intellicrack.bridges.frida_bridge.find_functions_named  # unused-method
intellicrack.bridges.frida_bridge.resolve_api  # unused-method
intellicrack.bridges.frida_bridge.replace_function  # unused-method
intellicrack.bridges.frida_bridge.enable_child_gating  # unused-method
intellicrack.bridges.frida_bridge.disable_child_gating  # unused-method
intellicrack.bridges.frida_bridge.get_pending_children  # unused-method
intellicrack.bridges.frida_bridge.resume_child  # unused-method
intellicrack.bridges.frida_bridge.enable_crash_reporting  # unused-method
intellicrack.bridges.frida_bridge.get_crashes  # unused-method
intellicrack.bridges.ghidra.get_function  # unused-method
intellicrack.bridges.ghidra.search_bytes  # unused-method
intellicrack.bridges.ghidra.rename_function  # unused-method
intellicrack.bridges.ghidra.add_comment  # unused-method
intellicrack.bridges.ghidra.get_data_type  # unused-method
intellicrack.bridges.ghidra.set_data_type  # unused-method
intellicrack.bridges.ghidra.execute_script  # unused-method
intellicrack.bridges.ghidra.set_label  # unused-method
intellicrack.bridges.ghidra.get_labels  # unused-method
intellicrack.bridges.ghidra.create_bookmark  # unused-method
intellicrack.bridges.ghidra.get_bookmarks  # unused-method
intellicrack.bridges.ghidra.create_function  # unused-method
intellicrack.bridges.ghidra.delete_function  # unused-method
intellicrack.bridges.ghidra.edit_function_signature  # unused-method
intellicrack.bridges.ghidra.set_function_variable_type  # unused-method
intellicrack.bridges.ghidra.define_structure  # unused-method
intellicrack.bridges.ghidra.get_structures  # unused-method
intellicrack.bridges.ghidra.apply_structure_at  # unused-method
intellicrack.bridges.ghidra.get_call_graph  # unused-method
intellicrack.bridges.ghidra.get_segments  # unused-method
intellicrack.bridges.ghidra.get_program_info  # unused-method
intellicrack.bridges.hex_editor.open_file  # unused-method
intellicrack.bridges.hex_editor.close_file  # unused-method
intellicrack.bridges.hex_editor.get_cursor_position  # unused-method
intellicrack.bridges.hex_editor.select_range  # unused-method
intellicrack.bridges.hex_editor.get_selection  # unused-method
intellicrack.bridges.hex_editor.inspect_data_at  # unused-method
intellicrack.bridges.hex_editor.calculate_hash  # unused-method
intellicrack.bridges.hex_editor.get_byte_statistics  # unused-method
intellicrack.bridges.hex_editor.register_template  # unused-method
intellicrack.bridges.hex_editor.compile_pattern  # unused-method
intellicrack.bridges.hex_editor.execute_pattern  # unused-method
intellicrack.bridges.hex_editor.execute_pattern_file  # unused-method
intellicrack.bridges.hex_editor.list_hexpat_patterns  # unused-method
intellicrack.bridges.hex_editor.auto_detect_pattern  # unused-method
intellicrack.bridges.hex_editor.export_template  # unused-method
intellicrack.bridges.hex_editor.compare_files  # unused-method
intellicrack.bridges.hex_editor.save_as  # unused-method
intellicrack.bridges.hex_editor.calculate_hash_range  # unused-method
intellicrack.bridges.hex_editor.get_context_for_ai  # unused-method
intellicrack.bridges.hex_editor.get_entropy_map  # unused-method
intellicrack.bridges.hex_editor.get_byte_distribution  # unused-method
intellicrack.bridges.hex_editor.get_byte_type_distribution  # unused-method
intellicrack.bridges.hex_editor.get_digram_matrix  # unused-method
intellicrack.bridges.hex_editor.get_content_classification  # unused-method
intellicrack.bridges.hex_editor.yara_scan  # unused-method
intellicrack.bridges.hex_editor.yara_scan_files  # unused-method
intellicrack.bridges.hex_editor.apply_transform  # unused-method
intellicrack.bridges.hex_editor.apply_pipeline  # unused-method
intellicrack.bridges.hex_editor.calculate_hash_custom_crc  # unused-method
intellicrack.bridges.hex_editor.export_patches  # unused-method
intellicrack.bridges.hex_editor.import_patches  # unused-method
intellicrack.bridges.hex_editor.add_highlight_rule  # unused-method
intellicrack.bridges.hex_editor.remove_highlight_rule  # unused-method
intellicrack.bridges.hex_editor.list_highlight_rules  # unused-method
intellicrack.bridges.hex_state.clear_selection  # unused-method
intellicrack.bridges.process.open_process  # unused-method
intellicrack.bridges.process.suspend  # unused-method
intellicrack.bridges.process.protect  # unused-method
intellicrack.bridges.process.search_pattern  # unused-method
intellicrack.bridges.process.inject_dll  # unused-method
intellicrack.bridges.process.get_process_info  # unused-method
intellicrack.bridges.sandbox_bridge.copy_to  # unused-method
intellicrack.bridges.sandbox_bridge.copy_from  # unused-method
intellicrack.bridges.sandbox_bridge.snapshot_create  # unused-method
intellicrack.bridges.sandbox_bridge.snapshot_restore  # unused-method
intellicrack.bridges.sandbox_bridge.snapshot_list  # unused-method
intellicrack.bridges.sandbox_bridge.snapshot_delete  # unused-method
intellicrack.bridges.schemas.input_schema  # unused-variable
intellicrack.bridges.x64dbg.MAX_LOCAL_VARS  # unused-variable
intellicrack.bridges.x64dbg.dwFlags  # unused-attribute
intellicrack.bridges.x64dbg.wShowWindow  # unused-attribute
intellicrack.bridges.x64dbg.set_watchpoint  # unused-method
intellicrack.bridges.x64dbg.remove_watchpoint  # unused-method
intellicrack.bridges.x64dbg.get_watchpoints  # unused-method
intellicrack.bridges.x64dbg.allocate_memory  # unused-method
intellicrack.bridges.x64dbg.free_memory  # unused-method
intellicrack.bridges.x64dbg.assemble_at  # unused-method
intellicrack.bridges.x64dbg.get_process_info  # unused-method
intellicrack.bridges.x64dbg.find_pattern  # unused-method
intellicrack.bridges.x64dbg.run_to  # unused-method
intellicrack.bridges.x64dbg.execute_til_return  # unused-method
intellicrack.bridges.x64dbg.skip_instruction  # unused-method
intellicrack.bridges.x64dbg.set_ip  # unused-method
intellicrack.bridges.x64dbg.set_label  # unused-method
intellicrack.bridges.x64dbg.get_labels  # unused-method
intellicrack.bridges.x64dbg.set_comment  # unused-method
intellicrack.bridges.x64dbg.get_comments  # unused-method
intellicrack.bridges.x64dbg.enable_breakpoint  # unused-method
intellicrack.bridges.x64dbg.disable_breakpoint  # unused-method
intellicrack.bridges.x64dbg.set_breakpoint_on_api  # unused-method
intellicrack.bridges.x64dbg.dump_memory_to_file  # unused-method
intellicrack.bridges.x64dbg.get_module_sections  # unused-method
intellicrack.bridges.x64dbg.get_module_exports  # unused-method
intellicrack.bridges.x64dbg.trace_start  # unused-method
intellicrack.bridges.x64dbg.trace_stop  # unused-method
intellicrack.bridges.x64dbg.set_exception_config  # unused-method
intellicrack.core.disassembler.detail  # unused-attribute
intellicrack.core.hexpat.ast_nodes.is_const  # unused-variable
intellicrack.core.hexpat.interpreter.execute_bytes  # unused-method
intellicrack.core.hexpat.pattern_registry.get_pattern  # unused-method
intellicrack.core.hexpat.stdlib.set_array_index  # unused-method
intellicrack.core.process_manager.ASYNC_SUBPROCESS  # unused-variable
intellicrack.core.session.row_factory  # unused-attribute
intellicrack.core.template_manager._config_dir  # unused-attribute
intellicrack.core.template_manager.list_all_templates  # unused-method
intellicrack.core.template_manager.save_user_template  # unused-method
intellicrack.core.template_manager.delete_user_template  # unused-method
intellicrack.core.template_manager.list_hexpat_patterns  # unused-method
intellicrack.core.template_manager.list_hexpat_by_category  # unused-method
intellicrack.core.tools.get_process_bridge  # unused-method
intellicrack.core.tools.get_sandbox_bridge  # unused-method
intellicrack.core.types.thinking_content  # unused-variable
intellicrack.core.types.rflags  # unused-variable
intellicrack.core.yara_scanner.scan_data_async  # unused-method
intellicrack.core.yara_scanner.scan_file_async  # unused-method
intellicrack.credentials.oauth.log_request  # unused-method
intellicrack.credentials.oauth.authorize_google  # unused-function
intellicrack.providers.anthropic._credentials  # unused-attribute
intellicrack.providers.base.input_schema  # unused-variable
intellicrack.providers.base._credentials  # unused-attribute
intellicrack.providers.base._credentials  # unused-attribute
intellicrack.providers.google._credentials  # unused-attribute
intellicrack.providers.grok.tool_call_id  # unused-variable
intellicrack.providers.grok._credentials  # unused-attribute
intellicrack.providers.huggingface._credentials  # unused-attribute
intellicrack.providers.local_transformers._credentials  # unused-attribute
intellicrack.providers.ollama._credentials  # unused-attribute
intellicrack.providers.openai.tool_call_id  # unused-variable
intellicrack.providers.openai._credentials  # unused-attribute
intellicrack.providers.openrouter._credentials  # unused-attribute
intellicrack.providers.registry.get_active_or_raise  # unused-method
intellicrack.sandbox.base.value_name  # unused-variable
intellicrack.sandbox.base.value_data  # unused-variable
intellicrack.sandbox.base.local_address  # unused-variable
intellicrack.sandbox.base.local_port  # unused-variable
intellicrack.sandbox.base.remote_address  # unused-variable
intellicrack.sandbox.base.remote_port  # unused-variable
intellicrack.sandbox.base.bytes_sent  # unused-variable
intellicrack.sandbox.base.bytes_received  # unused-variable
intellicrack.sandbox.base.get_status_info  # unused-method
intellicrack.ui.app._model_browse_worker  # unused-attribute
intellicrack.ui.app._script_validator  # unused-attribute
intellicrack.ui.app._script_validator  # unused-attribute
intellicrack.ui.app._model_browse_worker  # unused-attribute
intellicrack.ui.panels.cutter_panel._asm_highlighter  # unused-attribute
intellicrack.ui.panels.cutter_panel._c_highlighter  # unused-attribute
intellicrack.ui.panels.hex_editor._base.hex_state_available  # unused-variable
intellicrack.ui.panels.hex_editor._base.hex_state_available  # unused-variable
intellicrack.ui.panels.hex_editor._base.transform_pipeline_available  # unused-variable
intellicrack.ui.panels.hex_editor._base.transform_pipeline_available  # unused-variable
intellicrack.ui.panels.hex_editor._bookmarks._on_bookmark_double_clicked  # unused-method
intellicrack.ui.panels.hex_editor._statistics.classification_block_size  # unused-variable
intellicrack.ui.panels.hex_editor_widget.DISPLAY_MODES  # unused-variable
intellicrack.ui.panels.hex_editor_widget.DISPLAY_MODES  # unused-variable
intellicrack.ui.panels.hex_editor_widget.add_highlight_rule  # unused-method
intellicrack.ui.panels.hex_editor_widget.remove_highlight_rule  # unused-method
intellicrack.ui.panels.qt_compat.edit_table_item  # unused-function
intellicrack.ui.panels.stack_viewer.set_data_source  # unused-method
intellicrack.ui.resources.icon_manager.icon_exists  # unused-method
intellicrack.ui.tools.get_highlighter  # unused-method
intellicrack.ui.tools._ghidra_bridge  # unused-attribute
intellicrack.ui.tools._cutter_bridge  # unused-attribute
intellicrack.ui.tools._cutter_bridge  # unused-attribute
intellicrack.ui.tools._ghidra_bridge  # unused-attribute
intellicrack.bridges.hex_editor.encode_text  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.list_process_regions  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.test_in_sandbox  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.open_process_memory  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.set_state_holder  # unused-method (getattr dispatch)
intellicrack.bridges.hex_editor._cursor_position  # unused-attribute (state for get_cursor_position)
intellicrack.credentials.oauth.OAuthFlowType  # unused-class (exported in __init__)
intellicrack.sandbox.base.old_path  # unused-variable (TypedDict field)
intellicrack.sandbox.base.environment_variables  # unused-variable (dataclass field)
intellicrack.sandbox.base.started_at  # unused-variable (dataclass field)
intellicrack.sandbox.qemu.started_at  # unused-attribute (writes dataclass field)
intellicrack.sandbox.windows.started_at  # unused-attribute (writes dataclass field)
intellicrack.ui.panels.cutter_panel._decompile_btn  # unused-attribute (Qt GC prevention)
intellicrack.ui.panels.cutter_panel._graph_btn  # unused-attribute (Qt GC prevention)
intellicrack.ui.panels.frida_panel._refresh_devices_btn  # unused-attribute (Qt GC prevention)
intellicrack.ui.panels.hex_editor.panel._undo_btn  # unused-attribute (Qt GC prevention)
intellicrack.ui.panels.hex_editor.panel._redo_btn  # unused-attribute (Qt GC prevention)
intellicrack.ui.panels.hex_editor.panel._find_next_btn  # unused-attribute (Qt GC prevention)
intellicrack.ui.panels.hex_editor.panel._find_prev_btn  # unused-attribute (Qt GC prevention)
intellicrack.bridges.ghidra._PE_MAGIC  # unused-variable (API surface constant)
intellicrack.bridges.installer._ERR_EXTRACTION_FAILED  # unused-variable (API surface constant)
intellicrack.core.hexpat.interpreter._PATTERNS_DIR  # unused-variable (API surface constant)
intellicrack.core.hexpat.preprocessor._PRAGMA_DEBUG_RE  # unused-variable (API surface constant)
intellicrack.providers.anthropic._MSG_NO_MODELS_AVAILABLE  # unused-variable (API surface constant)
intellicrack.providers.registry._MSG_NO_ACTIVE_PROVIDER  # unused-variable (API surface constant)
intellicrack.providers.model_loader._BF16_MULTIPLIER  # unused-variable (API surface constant)
intellicrack.providers.xpu_utils._B580_DEVICE_IDS  # unused-variable (API surface constant)
intellicrack.providers.xpu_utils._INTEL_VENDOR_ID  # unused-variable (API surface constant)
intellicrack.ui.panels.vnc_widget._PIXEL_FORMAT_32BIT  # unused-variable (API surface constant)
intellicrack.ui.panels.hex_editor._base.hex_state_available  # unused-variable (availability flag)
intellicrack.ui.panels.hex_editor._base.transform_pipeline_available  # unused-variable (availability flag)
intellicrack.ui.panels.hex_editor_widget.DISPLAY_MODES  # unused-variable (API surface constant)
intellicrack.credentials.oauth.AUTHORIZATION_CODE  # unused-variable (enum member)
intellicrack.core.process_manager.ASYNC_SUBPROCESS  # unused-variable (enum member)
intellicrack.ui.resources.font_manager.DEFAULT_CODE_FONT  # unused-variable (API surface constant)
intellicrack.providers.huggingface._api_token  # unused-attribute (lifecycle tracking)
intellicrack.providers.model_loader.use_flash_attention  # unused-variable (config extraction)
intellicrack.providers.model_loader.quantization_config  # unused-variable (config extraction)
intellicrack.bridges.hex_editor.execute_pattern_bytes  # unused-method (bridge tool_definitions dispatch)
intellicrack.ui.tools.connect_hex_widget_to_tools  # unused-method (called by host panel at runtime)

# === Vulture audit 2026-04-24: comprehensive FP whitelist ===

# Frida bridge methods - dispatched via tool_definitions name="frida.<m>" (getattr in core/tools.py:480)
intellicrack.bridges.frida_bridge.post_message  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.eternalize_script  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.rpc_call  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.create_cancellable  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.patch_code  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.allocate_string  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.enumerate_symbols  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.load_module  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.find_module_by_address  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.find_functions_matching  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.disassemble_instruction  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.set_exception_handler  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.revert_hook  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.flush_interceptor  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.call_system_function  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.stalker_add_call_probe  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.stalker_remove_call_probe  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.objc_enumerate_classes  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.objc_enumerate_protocols  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.objc_enumerate_loaded_classes  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.objc_choose  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.objc_get_class_methods  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.objc_hook_method  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.java_enumerate_loaded_classes  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.java_choose  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.java_use  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.java_hook_method  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.java_deoptimize  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.create_cmodule  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.kernel_enumerate_modules  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.kernel_enumerate_ranges  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.kernel_read  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.kernel_write  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.kernel_alloc  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.kernel_protect  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.socket_listen  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.socket_connect  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.socket_type  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.socket_local_address  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.socket_peer_address  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.file_read_target  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.file_write_target  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.sqlite_open  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.sqlite_exec  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.sqlite_dump  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.write_code  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.cloak_add_thread  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.cloak_remove_thread  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.cloak_add_range  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.cloak_remove_range  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.compile_typescript  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.monitor_path  # unused-method (tool_definitions dispatch)
intellicrack.bridges.frida_bridge.stop_monitor  # unused-method (tool_definitions dispatch)

# Cutter bridge methods - dispatched via _tf("<name>") helper / tested
intellicrack.bridges.cutter.R2_COMMAND_TIMEOUT  # unused-variable (tested in test_process_cleanup.py)
intellicrack.bridges.cutter.r2_cmd  # unused-method (tested in test_process_cleanup.py)
intellicrack.bridges.cutter.get_debug_info  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_classes  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_callgraph  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_vtables  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_syscalls  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.add_flag  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.resolve_flag  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_unions  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_typedefs  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_function_types  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.import_c_header  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.esil_emulate_function  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.esil_set_pc  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.get_zignatures  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.generate_zignatures  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.add_zignature  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.search_zignatures  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.save_project  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.open_project  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.list_projects  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.set_config  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_xor  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_add  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_sub  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_from_file  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_to_file  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_value  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.write_string  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.search_string_live  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.search_assembly_pattern  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.search_crypto_constants  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.search_magic  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.search_value  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.compare_bytes  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.compare_disassembly  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.hexdump_words  # unused-method (tool_definitions dispatch)
intellicrack.bridges.cutter.disassemble_function  # unused-method (tool_definitions dispatch)

# Ghidra bridge methods - dispatched via tool_definitions name="ghidra.<m>" / tested
intellicrack.bridges.ghidra.create_bridge_script  # unused-method (tested in test_process_cleanup.py)
intellicrack.bridges.ghidra.get_register_value  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.add_reference  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.delete_reference  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.get_instruction_flow  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.create_data_type  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.create_data  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.get_program_tree  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.get_properties  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.get_thunk_info  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.get_external_references  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.remove_label  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.add_thunk  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.remove_thunk  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.add_external_reference  # unused-method (tool_definitions dispatch)
intellicrack.bridges.ghidra.remove_external_reference  # unused-method (tool_definitions dispatch)

# Hex editor bridge methods - dispatched via tool_definitions name="hex_editor.<m>"
intellicrack.bridges.hex_editor.save_to_sandbox  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.get_entropy  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.set_va_base  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.auto_detect_va_mappings  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.get_strings  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.generate_structure_bookmarks  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.export_annotated_html  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.export_annotated_pdf  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.snap_to_alignment  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.set_alignment_grid  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.run_python_script  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.set_chunk_size  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.set_memory_budget  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.get_color_mode  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.scan_die_signatures  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.scan_clamav_signatures  # unused-method (tool_definitions dispatch)
intellicrack.bridges.hex_editor.scan_custom_signatures  # unused-method (tool_definitions dispatch)

# x64dbg bridge methods - dispatched via tool_definitions name="x64dbg.<m>"
intellicrack.bridges.x64dbg.get_entry_point  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.get_module_imports  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.find_references  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.find_string_references  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.find_intermodular_calls  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.get_function_cfg  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.clear_database  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.restore_patch  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.set_thread_name  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.get_pe_directories  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.add_watch  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.remove_watch  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.get_watches  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.set_logging_breakpoint  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.configure_breakpoint  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.set_dll_breakpoint  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.get_trace_record  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.step_count  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.animate_start  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.animate_stop  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.analyze_entropy  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.script_load  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.script_run  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.script_cmd  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.script_abort  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.plugin_load  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.plugin_unload  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.plugin_list  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.detect_anti_debug  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.patch_anti_debug  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.reconstruct_imports  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.goto_address  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.break_on_tls_callbacks  # unused-method (tool_definitions dispatch)
intellicrack.bridges.x64dbg.PrivilegeCount  # unused-attribute (TOKEN_PRIVILEGES ctypes field read by AdjustTokenPrivileges)

# Process bridge methods + Win32 ctypes struct fields read C-side by Windows API
intellicrack.bridges.process.list_detailed  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.pipe_read  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.pipe_write  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.device_open  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.device_ioctl  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.device_close  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.create_section  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.map_section  # unused-method (tool_definitions dispatch)
intellicrack.bridges.process.PrivilegeCount  # unused-attribute (TOKEN_PRIVILEGES ctypes field)
intellicrack.bridges.process.ContextFlags  # unused-attribute (CONTEXT/WOW64_CONTEXT ctypes field read by GetThreadContext)
intellicrack.bridges.process.Mode  # unused-attribute (STACKFRAME64.AddrPC/AddrFrame/AddrStack ctypes field)
intellicrack.bridges.process.SizeOfStruct  # unused-attribute (SYMBOL_INFO ctypes field read by SymFromAddr)
intellicrack.bridges.process.MaxNameLen  # unused-attribute (SYMBOL_INFO ctypes field read by SymFromAddr)

# Sandbox bridge methods - dispatched via tool_definitions name="sandbox.<m>"
intellicrack.bridges.sandbox_bridge.anti_evasion  # unused-method (tool_definitions dispatch)
intellicrack.bridges.sandbox_bridge.detect_c2  # unused-method (tool_definitions dispatch)
intellicrack.bridges.sandbox_bridge.diff  # unused-method (tool_definitions dispatch)

# Win32 types - asserted in test_win32_types.py / ctypes self-referential _fields_
intellicrack.bridges._win32_types.THREAD_ALL_ACCESS  # unused-variable (tested in test_win32_types.py)
intellicrack.bridges._win32_types.TH32CS_SNAPALL  # unused-variable (tested in test_win32_types.py)
intellicrack.bridges._win32_types.THREAD_STATE_NAMES  # unused-variable (tested in test_win32_types.py)
intellicrack.bridges._win32_types.get_kernel32  # unused-function (tested in test_win32_types.py)
intellicrack.bridges._win32_types.get_psapi  # unused-function (tested in test_win32_types.py)
intellicrack.bridges._win32_types._fields_  # unused-attribute (EXCEPTION_REGISTRATION_RECORD self-ref ctypes)

# Bridges base - dataclass field declarations consumed by @dataclass
intellicrack.bridges.base.context_before  # unused-variable (MemorySearchResult dataclass field)
intellicrack.bridges.base.context_after  # unused-variable (MemorySearchResult dataclass field)

# Sandbox base TypedDict fields (consumed by typing metaclass machinery)
intellicrack.sandbox.base.service_name  # unused-variable (TypedDict ServiceChange field)
intellicrack.sandbox.base.start_type  # unused-variable (TypedDict ServiceChange field)
intellicrack.sandbox.base.object_type  # unused-variable (TypedDict KernelObjectActivity field)
intellicrack.sandbox.base.source_pid  # unused-variable (TypedDict InjectionEvent field)
intellicrack.sandbox.base.injection_type  # unused-variable (TypedDict InjectionEvent field)
intellicrack.sandbox.base.cpu_percent  # unused-variable (TypedDict ResourceSample field)
intellicrack.sandbox.base.disk_read_bytes  # unused-variable (TypedDict ResourceSample field)
intellicrack.sandbox.base.disk_write_bytes  # unused-variable (TypedDict ResourceSample field)
intellicrack.sandbox.base.net_sent_bytes  # unused-variable (TypedDict ResourceSample field)
intellicrack.sandbox.base.net_recv_bytes  # unused-variable (TypedDict ResourceSample field)
intellicrack.sandbox.base.content_preview  # unused-variable (TypedDict ClipboardEvent field)
intellicrack.sandbox.base.signature_name  # unused-variable (TypedDict BehaviorMatch field)
intellicrack.sandbox.base.evidence  # unused-variable (TypedDict BehaviorMatch field)
intellicrack.sandbox.base.mitre_attack_id  # unused-variable (TypedDict BehaviorMatch field)

# Sandbox manager / qemu - tested
intellicrack.sandbox.manager.cleanup_stale  # unused-method (tested in test_manager.py)
intellicrack.sandbox.qemu.PIDFILE_MAX_RETRIES  # unused-variable (tested in test_process_cleanup.py)
intellicrack.sandbox.qemu.PIDFILE_RETRY_DELAY  # unused-variable (tested in test_process_cleanup.py)

# core/_subprocess.py - public attributes mirroring subprocess.STARTUPINFO API surface
intellicrack.core._subprocess.hStdInput  # unused-attribute (mirrors subprocess.STARTUPINFO API)
intellicrack.core._subprocess.hStdOutput  # unused-attribute (mirrors subprocess.STARTUPINFO API)
intellicrack.core._subprocess.hStdError  # unused-attribute (mirrors subprocess.STARTUPINFO API)
intellicrack.core._subprocess.lpAttributeList  # unused-attribute (mirrors subprocess.STARTUPINFO API)

# Providers - TypedDict fields consumed by metaclass / Protocol used in cast() / tested
intellicrack.providers.ollama.modified_at  # unused-variable (TypedDict OllamaTagEntry field)
intellicrack.providers.ollama.modelfile  # unused-variable (TypedDict OllamaShowResponse field)
intellicrack.providers.ollama.total_duration  # unused-variable (TypedDict OllamaGenerateResponse field)
intellicrack.providers.ollama.load_duration  # unused-variable (TypedDict OllamaGenerateResponse field)
intellicrack.providers.ollama.prompt_eval_count  # unused-variable (TypedDict OllamaGenerateResponse field)
intellicrack.providers.ollama.prompt_eval_duration  # unused-variable (TypedDict OllamaGenerateResponse field)
intellicrack.providers.ollama.eval_count  # unused-variable (TypedDict OllamaGenerateResponse field)
intellicrack.providers.ollama.eval_duration  # unused-variable (TypedDict OllamaGenerateResponse field)
intellicrack.providers.ollama.embedding  # unused-variable (TypedDict OllamaEmbeddingsResponse field)
intellicrack.providers.ollama.size_vram  # unused-variable (TypedDict OllamaRunningModel field)
intellicrack.providers.base.get_pending_usage  # unused-method (tested in tests/test_providers)
intellicrack.providers.base.get_pending_thinking  # unused-method (tested in tests/test_providers)
intellicrack.providers.huggingface._ChatCompletionCallable  # unused-class (Protocol used in cast() at L508,L649)

# core/types.py - dataclass field declarations / AttachError used in tests
intellicrack.core.types.methods  # unused-variable (ClassInfo/VtableInfo dataclass field)
intellicrack.core.types.jump  # unused-variable (BlockInfo dataclass field)
intellicrack.core.types.fail  # unused-variable (BlockInfo dataclass field)
intellicrack.core.types.next_address  # unused-variable (FridaInstructionInfo dataclass field)
intellicrack.core.types.errno  # unused-variable (SystemCallResult dataclass field)
intellicrack.core.types.AttachError  # unused-class (instantiated in tests/test_core/test_types.py)

# core/logging.py - tested
intellicrack.core.logging.log_binary_operation  # unused-function (tested in test_logging.py)
intellicrack.core.logging.OperationTimer  # unused-class (tested in test_logging.py)

# core/hexpat - frozen dataclass field / dead-allowlist intentional API
intellicrack.core.hexpat.ast_nodes.value_end  # unused-variable (EnumEntry frozen dataclass field)
intellicrack.core.hexpat.interpreter.can_compile_to_json  # unused-method (intentional API; in .dead-allowlist)

# main.py - tested entry-point initialization wrappers
intellicrack.main.init_model_discovery  # unused-function (tested in tests/test_providers)
intellicrack.main.init_script_engine  # unused-function (tested in test_main.py)
intellicrack.main.init_template_manager  # unused-function (tested in test_main.py)

# UI tools - dynamic getattr in close_embedded_tools()
intellicrack.ui.tools.ghidra_bridge  # unused-attribute (read via getattr in close_embedded_tools)
intellicrack.ui.tools.cutter_bridge  # unused-attribute (read via getattr in close_embedded_tools)
intellicrack.ui.tools.process_bridge  # unused-attribute (read via getattr in close_embedded_tools)

# UI app - intentional GC retention for Qt async workers / app-scoped instances / tested
intellicrack.ui.app.model_browse_worker  # unused-attribute (Qt AsyncWorker GC retention)
intellicrack.ui.app._script_generator  # unused-attribute (intentional app-scoped retention)
intellicrack.ui.app.on_open_x64dbg  # unused-method (tested in test_app_embedded_tools.py)
intellicrack.ui.app.on_open_cutter  # unused-method (tested in test_app_embedded_tools.py)

# UI panels - Qt GC prevention / QSyntaxHighlighter retention / tested code
intellicrack.ui.panels.cutter_panel._patch_btn  # unused-attribute (Qt GC prevention - toolbar button)
intellicrack.ui.panels.cutter_panel._goto_btn  # unused-attribute (Qt GC prevention - toolbar button)
intellicrack.ui.panels.cutter_panel._find_func_btn  # unused-attribute (Qt GC prevention - toolbar button)
intellicrack.ui.panels.ghidra_panel._debug_info_btn  # unused-attribute (Qt GC prevention - toolbar button)
intellicrack.ui.panels.ghidra_panel._diff_btn  # unused-attribute (Qt GC prevention - toolbar button)
intellicrack.ui.panels.frida_panel._js_highlighter  # unused-attribute (QSyntaxHighlighter document retention)
intellicrack.ui.panels.sandbox_panel.set_sandbox_manager  # unused-method (tested in test_sandbox_panel_fixes.py)
intellicrack.ui.panels.hxd_panel.find_hxd_executable  # unused-function (tested in test_hxd_panel.py)
intellicrack.ui.panels.hxd_panel.HxDPanel  # unused-class (tested in test_hxd_panel.py)
intellicrack.ui.panels.hxd_panel.terminate_existing  # unused-method (tested in test_hxd_panel.py)
intellicrack.ui.panels.vnc_widget.qt_key_to_x11  # unused-function (tested in test_vnc_widget.py)
intellicrack.ui.dialogs.splash_screen._progress_bar  # unused-attribute (hasattr-tested in test_splash_screen.py)
intellicrack.ui.dialogs.splash_screen.mark_stage_failed  # unused-method (tested in test_splash_screen.py)
intellicrack.ui.xpu_status.XPUStatusDialog  # unused-class (tested in test_xpu_status.py)

# ui/win32_embed.py - cast() string forward reference / tested constants
intellicrack.ui.win32_embed.voidptr  # unused-import (string forward ref in cast("voidptr", hwnd) at L254)
intellicrack.ui.win32_embed.GW_OWNER  # unused-variable (tested in test_win32_embed.py)
intellicrack.ui.win32_embed.MAX_TITLE_LEN  # unused-variable (tested in test_win32_embed.py)
