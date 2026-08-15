/**
 * @file command_handler.h
 * @brief Command dispatcher for Intellicrack bridge
 *
 * Processes JSON commands received from Intellicrack and dispatches
 * them to appropriate x64dbg functions.
 */

#ifndef INTELLICRACK_COMMAND_HANDLER_H
#define INTELLICRACK_COMMAND_HANDLER_H

#include "pipe_server.h"
#include <string>
#include <unordered_map>
#include <functional>
#include <cstdint>
#include <set>

namespace intellicrack {

class CommandHandler {
public:
    CommandHandler();
    ~CommandHandler() = default;

    CommandHandler(const CommandHandler&) = delete;
    CommandHandler& operator=(const CommandHandler&) = delete;

    PipeResponse handle_command(const PipeMessage& msg);

private:
    using CommandFunc = std::function<PipeResponse(const PipeMessage&)>;
    std::unordered_map<std::string, CommandFunc> m_commands;

    void register_commands();

    static PipeResponse cmd_exec(const PipeMessage& msg);
    static PipeResponse cmd_run(const PipeMessage& msg);
    static PipeResponse cmd_pause(const PipeMessage& msg);
    static PipeResponse cmd_stop(const PipeMessage& msg);
    static PipeResponse cmd_step_into(const PipeMessage& msg);
    static PipeResponse cmd_step_over(const PipeMessage& msg);
    static PipeResponse cmd_step_out(const PipeMessage& msg);
    static PipeResponse cmd_run_to(const PipeMessage& msg);

    static PipeResponse cmd_bp_set(const PipeMessage& msg);
    static PipeResponse cmd_bp_remove(const PipeMessage& msg);
    static PipeResponse cmd_bp_list(const PipeMessage& msg);
    static PipeResponse cmd_bp_enable(const PipeMessage& msg);
    static PipeResponse cmd_bp_disable(const PipeMessage& msg);

    static PipeResponse cmd_wp_set(const PipeMessage& msg);
    static PipeResponse cmd_wp_remove(const PipeMessage& msg);
    static PipeResponse cmd_wp_list(const PipeMessage& msg);

    static PipeResponse cmd_reg_all(const PipeMessage& msg);
    static PipeResponse cmd_reg_get(const PipeMessage& msg);
    static PipeResponse cmd_reg_set(const PipeMessage& msg);

    static PipeResponse cmd_mem_read(const PipeMessage& msg);
    static PipeResponse cmd_mem_write(const PipeMessage& msg);
    static PipeResponse cmd_mem_map(const PipeMessage& msg);

    static PipeResponse cmd_mod_list(const PipeMessage& msg);
    static PipeResponse cmd_mod_base(const PipeMessage& msg);
    static PipeResponse cmd_mod_exports(const PipeMessage& msg);
    static PipeResponse cmd_mod_imports(const PipeMessage& msg);

    static PipeResponse cmd_disasm(const PipeMessage& msg);
    static PipeResponse cmd_assemble(const PipeMessage& msg);

    static PipeResponse cmd_goto(const PipeMessage& msg);
    static PipeResponse cmd_status(const PipeMessage& msg);
    static PipeResponse cmd_ping(const PipeMessage& msg);

    static PipeResponse cmd_lbl_list(const PipeMessage& msg);
    static PipeResponse cmd_cmt_list(const PipeMessage& msg);
    static PipeResponse cmd_stack_trace(const PipeMessage& msg);
    static PipeResponse cmd_eval(const PipeMessage& msg);
    static PipeResponse cmd_ref_search(const PipeMessage& msg);
    static PipeResponse cmd_cfg(const PipeMessage& msg);
    static PipeResponse cmd_patch_list(const PipeMessage& msg);
    static PipeResponse cmd_patch_restore(const PipeMessage& msg);
    static PipeResponse cmd_seh_chain(const PipeMessage& msg);
    static PipeResponse cmd_peb_read(const PipeMessage& msg);
    static PipeResponse cmd_teb_read(const PipeMessage& msg);
    static PipeResponse cmd_pe_directories(const PipeMessage& msg);
    static PipeResponse cmd_watch_add(const PipeMessage& msg);
    static PipeResponse cmd_watch_remove(const PipeMessage& msg);
    static PipeResponse cmd_watch_list(const PipeMessage& msg);
    static PipeResponse cmd_trace_record(const PipeMessage& msg);
    static PipeResponse cmd_trace_record_set(const PipeMessage& msg);
    static PipeResponse cmd_plugin_list(const PipeMessage& msg);
    static PipeResponse cmd_thread_detail(const PipeMessage& msg);

    static uint64_t parse_address(const std::string& addr_str);
    static std::string format_address(uint64_t addr);
    static std::string escape_json(const std::string& s);
};

extern CommandHandler g_command_handler;

}

#endif
