/**
 * @file command_handler.cpp
 * @brief Command dispatcher implementation for Intellicrack bridge
 */

#include "command_handler.h"
#include "intellicrack_bridge.h"

// The vendored x64dbg SDK headers trip C4324 (struct padded due to an
// alignment specifier) under /W4 on the 32-bit build. They are third-party
// and must not be modified, so scope the suppression to just their inclusion.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4324)
#endif
#include <pluginsdk/_plugins.h>
#include <pluginsdk/_scriptapi_memory.h>
#include <pluginsdk/_scriptapi_register.h>
#include <pluginsdk/_scriptapi_debug.h>
#include <pluginsdk/_scriptapi_module.h>
#include <pluginsdk/_scriptapi_misc.h>
#include <pluginsdk/_scriptapi_label.h>
#include <pluginsdk/_scriptapi_comment.h>
#include <pluginsdk/bridgemain.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cstdio>
#include <cstring>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <set>

namespace intellicrack {

namespace {

// Extract a JSON string value for `key` from `json`, resolving standard
// JSON backslash escapes. Unlike the lightweight positional scans used for
// numeric/hex parameters (which never contain quotes), this correctly
// handles values with embedded escaped quotes such as the quoted target
// path in `InitDebug "C:/path/to/file.exe"`.
bool extract_json_string(const std::string& json, const char* key, std::string& out) {
    std::string search = "\"" + std::string(key) + "\"";
    size_t key_pos = json.find(search);
    if (key_pos == std::string::npos) {
        return false;
    }

    size_t colon = json.find(':', key_pos + search.size());
    if (colon == std::string::npos) {
        return false;
    }

    size_t pos = colon + 1;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }
    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }

    std::string result;
    size_t i = pos + 1;
    bool closed = false;
    while (i < json.size()) {
        char c = json[i];
        if (c == '\\' && i + 1 < json.size()) {
            char n = json[i + 1];
            switch (n) {
                case '"':  result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/':  result.push_back('/'); break;
                case 'n':  result.push_back('\n'); break;
                case 't':  result.push_back('\t'); break;
                case 'r':  result.push_back('\r'); break;
                case 'b':  result.push_back('\b'); break;
                case 'f':  result.push_back('\f'); break;
                default:   result.push_back(n); break;
            }
            i += 2;
            continue;
        }
        if (c == '"') {
            closed = true;
            break;
        }
        result.push_back(c);
        i++;
    }

    if (!closed) {
        return false;
    }

    out = result;
    return true;
}

}  // namespace

CommandHandler g_command_handler;

CommandHandler::CommandHandler() {
    register_commands();
}

void CommandHandler::register_commands() {
    m_commands["exec"] = [this](const PipeMessage& m) { return cmd_exec(m); };
    m_commands["run"] = [this](const PipeMessage& m) { return cmd_run(m); };
    m_commands["pause"] = [this](const PipeMessage& m) { return cmd_pause(m); };
    m_commands["stop"] = [this](const PipeMessage& m) { return cmd_stop(m); };
    m_commands["step_into"] = [this](const PipeMessage& m) { return cmd_step_into(m); };
    m_commands["step_over"] = [this](const PipeMessage& m) { return cmd_step_over(m); };
    m_commands["step_out"] = [this](const PipeMessage& m) { return cmd_step_out(m); };
    m_commands["run_to"] = [this](const PipeMessage& m) { return cmd_run_to(m); };

    m_commands["bp_set"] = [this](const PipeMessage& m) { return cmd_bp_set(m); };
    m_commands["bp_remove"] = [this](const PipeMessage& m) { return cmd_bp_remove(m); };
    m_commands["bp_list"] = [this](const PipeMessage& m) { return cmd_bp_list(m); };
    m_commands["bp_enable"] = [this](const PipeMessage& m) { return cmd_bp_enable(m); };
    m_commands["bp_disable"] = [this](const PipeMessage& m) { return cmd_bp_disable(m); };

    m_commands["wp_set"] = [this](const PipeMessage& m) { return cmd_wp_set(m); };
    m_commands["wp_remove"] = [this](const PipeMessage& m) { return cmd_wp_remove(m); };
    m_commands["wp_list"] = [this](const PipeMessage& m) { return cmd_wp_list(m); };

    m_commands["reg_all"] = [this](const PipeMessage& m) { return cmd_reg_all(m); };
    m_commands["reg_get"] = [this](const PipeMessage& m) { return cmd_reg_get(m); };
    m_commands["reg_set"] = [this](const PipeMessage& m) { return cmd_reg_set(m); };

    m_commands["mem_read"] = [this](const PipeMessage& m) { return cmd_mem_read(m); };
    m_commands["mem_write"] = [this](const PipeMessage& m) { return cmd_mem_write(m); };
    m_commands["mem_map"] = [this](const PipeMessage& m) { return cmd_mem_map(m); };

    m_commands["mod_list"] = [this](const PipeMessage& m) { return cmd_mod_list(m); };
    m_commands["mod_base"] = [this](const PipeMessage& m) { return cmd_mod_base(m); };
    m_commands["mod_exports"] = [this](const PipeMessage& m) { return cmd_mod_exports(m); };
    m_commands["mod_imports"] = [this](const PipeMessage& m) { return cmd_mod_imports(m); };

    m_commands["disasm"] = [this](const PipeMessage& m) { return cmd_disasm(m); };
    m_commands["assemble"] = [this](const PipeMessage& m) { return cmd_assemble(m); };

    m_commands["goto"] = [this](const PipeMessage& m) { return cmd_goto(m); };
    m_commands["status"] = [this](const PipeMessage& m) { return cmd_status(m); };
    m_commands["ping"] = [this](const PipeMessage& m) { return cmd_ping(m); };

    m_commands["lbl_list"] = [this](const PipeMessage& m) { return cmd_lbl_list(m); };
    m_commands["cmt_list"] = [this](const PipeMessage& m) { return cmd_cmt_list(m); };
    m_commands["stack_trace"] = [this](const PipeMessage& m) { return cmd_stack_trace(m); };
    m_commands["eval"] = [this](const PipeMessage& m) { return cmd_eval(m); };
    m_commands["ref_search"] = [this](const PipeMessage& m) { return cmd_ref_search(m); };
    m_commands["cfg"] = [this](const PipeMessage& m) { return cmd_cfg(m); };
    m_commands["patch_list"] = [this](const PipeMessage& m) { return cmd_patch_list(m); };
    m_commands["patch_restore"] = [this](const PipeMessage& m) { return cmd_patch_restore(m); };
    m_commands["seh_chain"] = [this](const PipeMessage& m) { return cmd_seh_chain(m); };
    m_commands["peb_read"] = [this](const PipeMessage& m) { return cmd_peb_read(m); };
    m_commands["teb_read"] = [this](const PipeMessage& m) { return cmd_teb_read(m); };
    m_commands["pe_directories"] = [this](const PipeMessage& m) { return cmd_pe_directories(m); };
    m_commands["watch_add"] = [this](const PipeMessage& m) { return cmd_watch_add(m); };
    m_commands["watch_remove"] = [this](const PipeMessage& m) { return cmd_watch_remove(m); };
    m_commands["watch_list"] = [this](const PipeMessage& m) { return cmd_watch_list(m); };
    m_commands["trace_record"] = [this](const PipeMessage& m) { return cmd_trace_record(m); };
    m_commands["plugin_list"] = [this](const PipeMessage& m) { return cmd_plugin_list(m); };
    m_commands["thread_detail"] = [this](const PipeMessage& m) { return cmd_thread_detail(m); };
}

PipeResponse CommandHandler::handle_command(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;
    response.success = false;

    auto it = m_commands.find(msg.command);
    if (it != m_commands.end()) {
        return it->second(msg);
    }

    response.error = "Unknown command: " + msg.command;
    return response;
}

PipeResponse CommandHandler::cmd_exec(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    std::string cmd;
    if (!extract_json_string(msg.params, "command", cmd)) {
        response.success = false;
        response.error = "Missing or invalid 'command' parameter";
        return response;
    }

    bool result = DbgCmdExec(cmd.c_str());
    response.success = result;
    if (result) {
        response.result = "true";
    } else {
        response.error = "Command execution failed";
    }

    return response;
}

PipeResponse CommandHandler::cmd_run(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("run");
    g_state.paused = false;

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_pause(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("pause");
    g_state.paused = true;

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_stop(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("stop");
    g_state.debugging = false;
    g_state.paused = false;

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_step_into(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("sti");

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_step_over(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("sto");

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_step_out(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("rtr");

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_run_to(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'address' parameter";
        return response;
    }

    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bp %s, ss", addr_str.c_str());
    DbgCmdExec(cmd);
    DbgCmdExec("run");

    response.success = true;
    response.result = format_address(address);
    return response;
}

PipeResponse CommandHandler::cmd_bp_set(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'address' parameter";
        return response;
    }

    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    std::string bp_type = "software";
    size_t type_pos = msg.params.find("\"type\"");
    if (type_pos != std::string::npos) {
        size_t ts = msg.params.find('"', type_pos + 6);
        if (ts != std::string::npos) ts++;
        size_t te = msg.params.find('"', ts);
        if (te != std::string::npos) {
            bp_type = msg.params.substr(ts, te - ts);
        }
    }

    char cmd[128];
    bool result = false;

    if (bp_type == "hardware") {
        snprintf(cmd, sizeof(cmd), "bphws %s, x", addr_str.c_str());
        result = DbgCmdExec(cmd);
    } else if (bp_type == "memory") {
        size_t size_pos = msg.params.find("\"size\"");
        if (size_pos != std::string::npos) {
            size_t ss_start = size_pos + 6;
            while (ss_start < msg.params.length() && !isdigit(msg.params[ss_start])) ss_start++;
            size_t ss_end = ss_start;
            while (ss_end < msg.params.length() && isdigit(msg.params[ss_end])) ss_end++;
            if (ss_end > ss_start) {
                int mem_size = std::stoi(msg.params.substr(ss_start, ss_end - ss_start));
                snprintf(cmd, sizeof(cmd), "bpm %s, %d", addr_str.c_str(), mem_size);
            } else {
                snprintf(cmd, sizeof(cmd), "bpm %s", addr_str.c_str());
            }
        } else {
            snprintf(cmd, sizeof(cmd), "bpm %s", addr_str.c_str());
        }
        result = DbgCmdExec(cmd);
    } else {
        snprintf(cmd, sizeof(cmd), "bp %s", addr_str.c_str());
        result = DbgCmdExec(cmd);
    }

    response.success = result;
    if (result) {
        response.result = "\"" + format_address(address) + "\"";
    } else {
        response.error = "Failed to set breakpoint";
    }
    return response;
}

PipeResponse CommandHandler::cmd_bp_remove(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'address' parameter";
        return response;
    }

    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bc %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_bp_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    std::ostringstream ss;
    ss << "[";
    bool first_entry = true;

    struct BpTypeInfo {
        BPXTYPE type;
        const char* type_str;
    };
    BpTypeInfo bp_types[] = {
        { bp_normal,   "normal"   },
        { bp_hardware, "hardware" },
        { bp_memory,   "memory"   }
    };

    for (const auto& bpt : bp_types) {
        BPMAP bpmap;
        if (!DbgGetBpList(bpt.type, &bpmap)) {
            continue;
        }

        for (int i = 0; i < bpmap.count; i++) {
            if (!first_entry) ss << ",";
            first_entry = false;
            ss << "{\"address\":\"" << format_address(bpmap.bp[i].addr) << "\","
               << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
               << "\"type\":\"" << bpt.type_str << "\","
               << "\"hitCount\":" << bpmap.bp[i].hitCount << ","
               << "\"breakCondition\":\"" << escape_json(bpmap.bp[i].breakCondition) << "\""
               << "}";
        }

        if (bpmap.bp) {
            BridgeFree(bpmap.bp);
        }
    }

    ss << "]";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_bp_enable(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "be %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_bp_disable(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bd %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_wp_set(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t size_pos = msg.params.find("\"size\"");
    size_t type_pos = msg.params.find("\"access\"");

    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    std::string wp_type = "rw";
    if (type_pos != std::string::npos) {
        start = msg.params.find('"', type_pos + 8);
        if (start != std::string::npos) start++;
        end = msg.params.find('"', start);
        if (end != std::string::npos) {
            wp_type = msg.params.substr(start, end - start);
        }
    }

    int size = 4;
    if (size_pos != std::string::npos) {
        start = size_pos + 6;
        while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
        end = start;
        while (end < msg.params.length() && isdigit(msg.params[end])) end++;
        if (end > start) {
            size = std::stoi(msg.params.substr(start, end - start));
        }
    }

    char cmd[128];
    if (wp_type == "r" || wp_type == "read") {
        snprintf(cmd, sizeof(cmd), "bphws %s, r, %d", addr_str.c_str(), size);
    } else if (wp_type == "w" || wp_type == "write") {
        snprintf(cmd, sizeof(cmd), "bphws %s, w, %d", addr_str.c_str(), size);
    } else {
        snprintf(cmd, sizeof(cmd), "bphws %s, rw, %d", addr_str.c_str(), size);
    }

    bool result = DbgCmdExec(cmd);
    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_wp_remove(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bphwc %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_wp_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    BPMAP bpmap;
    if (!DbgGetBpList(bp_hardware, &bpmap)) {
        response.success = false;
        response.error = "Failed to get watchpoint list";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < bpmap.count; i++) {
        if (i > 0) ss << ",";
        ss << "{\"address\":\"" << format_address(bpmap.bp[i].addr) << "\","
           << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
           << "\"type\":\"hardware\""
           << "}";
    }

    ss << "]";

    if (bpmap.bp) {
        BridgeFree(bpmap.bp);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_reg_all(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    REGDUMP_AVX512 regdump;
    if (!DbgGetRegDumpEx(&regdump, sizeof(regdump))) {
        response.success = false;
        response.error = "Failed to get register dump";
        return response;
    }

    std::ostringstream ss;
    ss << "{";

#ifdef BUILD_X64
    ss << "\"rax\":\"" << format_address(regdump.regcontext.cax) << "\",";
    ss << "\"rbx\":\"" << format_address(regdump.regcontext.cbx) << "\",";
    ss << "\"rcx\":\"" << format_address(regdump.regcontext.ccx) << "\",";
    ss << "\"rdx\":\"" << format_address(regdump.regcontext.cdx) << "\",";
    ss << "\"rsi\":\"" << format_address(regdump.regcontext.csi) << "\",";
    ss << "\"rdi\":\"" << format_address(regdump.regcontext.cdi) << "\",";
    ss << "\"rbp\":\"" << format_address(regdump.regcontext.cbp) << "\",";
    ss << "\"rsp\":\"" << format_address(regdump.regcontext.csp) << "\",";
    ss << "\"rip\":\"" << format_address(regdump.regcontext.cip) << "\",";
    ss << "\"r8\":\"" << format_address(regdump.regcontext.r8) << "\",";
    ss << "\"r9\":\"" << format_address(regdump.regcontext.r9) << "\",";
    ss << "\"r10\":\"" << format_address(regdump.regcontext.r10) << "\",";
    ss << "\"r11\":\"" << format_address(regdump.regcontext.r11) << "\",";
    ss << "\"r12\":\"" << format_address(regdump.regcontext.r12) << "\",";
    ss << "\"r13\":\"" << format_address(regdump.regcontext.r13) << "\",";
    ss << "\"r14\":\"" << format_address(regdump.regcontext.r14) << "\",";
    ss << "\"r15\":\"" << format_address(regdump.regcontext.r15) << "\",";
#else
    ss << "\"eax\":\"" << format_address(regdump.regcontext.cax) << "\",";
    ss << "\"ebx\":\"" << format_address(regdump.regcontext.cbx) << "\",";
    ss << "\"ecx\":\"" << format_address(regdump.regcontext.ccx) << "\",";
    ss << "\"edx\":\"" << format_address(regdump.regcontext.cdx) << "\",";
    ss << "\"esi\":\"" << format_address(regdump.regcontext.csi) << "\",";
    ss << "\"edi\":\"" << format_address(regdump.regcontext.cdi) << "\",";
    ss << "\"ebp\":\"" << format_address(regdump.regcontext.cbp) << "\",";
    ss << "\"esp\":\"" << format_address(regdump.regcontext.csp) << "\",";
    ss << "\"eip\":\"" << format_address(regdump.regcontext.cip) << "\",";
#endif

    ss << "\"eflags\":\"" << format_address(regdump.regcontext.eflags) << "\"";
    ss << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_reg_get(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string reg_name = msg.params.substr(start, end - start);

    duint value = DbgValFromString(reg_name.c_str());

    response.success = true;
    response.result = "\"" + format_address(value) + "\"";
    return response;
}

PipeResponse CommandHandler::cmd_reg_set(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"register\"");
    size_t value_pos = msg.params.find("\"value\"");

    if (name_pos == std::string::npos || value_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'register' or 'value' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 10);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string reg_name = msg.params.substr(start, end - start);

    start = msg.params.find('"', value_pos + 7);
    if (start != std::string::npos) start++;
    end = msg.params.find('"', start);
    std::string value_str = msg.params.substr(start, end - start);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "mov %s, %s", reg_name.c_str(), value_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_mem_read(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t size_pos = msg.params.find("\"size\"");

    if (addr_pos == std::string::npos || size_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' or 'size' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    start = size_pos + 6;
    while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
    end = start;
    while (end < msg.params.length() && isdigit(msg.params[end])) end++;
    int size = std::stoi(msg.params.substr(start, end - start));

    if (size <= 0 || size > 65536) {
        response.success = false;
        response.error = "Invalid size parameter";
        return response;
    }

    std::vector<uint8_t> buffer(size);
    if (!DbgMemRead(static_cast<duint>(address), buffer.data(), size)) {
        response.success = false;
        response.error = "Failed to read memory";
        return response;
    }

    std::ostringstream ss;
    ss << "\"";
    for (int i = 0; i < size; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
    }
    ss << "\"";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mem_write(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t data_pos = msg.params.find("\"data\"");

    if (addr_pos == std::string::npos || data_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' or 'data' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    start = msg.params.find('"', data_pos + 6);
    if (start != std::string::npos) start++;
    end = msg.params.find('"', start);
    std::string hex_data = msg.params.substr(start, end - start);

    std::vector<uint8_t> data;
    for (size_t i = 0; i + 1 < hex_data.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex_data.substr(i, 2), nullptr, 16));
        data.push_back(byte);
    }

    if (data.empty()) {
        response.success = false;
        response.error = "No data to write";
        return response;
    }

    bool result = DbgMemWrite(static_cast<duint>(address), data.data(), data.size());

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_mem_map(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    MEMMAP memmap;
    if (!DbgMemMap(&memmap)) {
        response.success = false;
        response.error = "Failed to get memory map";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < memmap.count; i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"base\":\"" << format_address(reinterpret_cast<uintptr_t>(memmap.page[i].mbi.BaseAddress)) << "\",";
        ss << "\"size\":" << memmap.page[i].mbi.RegionSize << ",";
        ss << "\"protect\":" << memmap.page[i].mbi.Protect << ",";
        ss << "\"type\":" << memmap.page[i].mbi.Type;
        ss << "}";
    }

    ss << "]";

    if (memmap.page) {
        BridgeFree(memmap.page);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mod_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    BridgeList<Script::Module::ModuleInfo> modules;
    Script::Module::GetList(&modules);

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < modules.Count(); i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"name\":\"" << escape_json(modules[i].name) << "\",";
        ss << "\"path\":\"" << escape_json(modules[i].path) << "\",";
        ss << "\"base\":\"" << format_address(modules[i].base) << "\",";
        ss << "\"size\":" << modules[i].size << ",";
        ss << "\"entry\":\"" << format_address(modules[i].entry) << "\"";
        ss << "}";
    }

    ss << "]";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mod_base(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());

    response.success = base != 0;
    if (base) {
        response.result = "\"" + format_address(base) + "\"";
    } else {
        response.error = "Module not found";
    }
    return response;
}

PipeResponse CommandHandler::cmd_mod_exports(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());
    if (!base) {
        response.success = false;
        response.error = "Module not found";
        return response;
    }

    Script::Module::ModuleInfo modInfo = {};
    if (!Script::Module::InfoFromAddr(base, &modInfo)) {
        response.success = false;
        response.error = "Failed to get module info";
        return response;
    }

    ListInfo export_list = {};
    if (!Script::Module::GetExports(&modInfo, &export_list)) {
        response.success = true;
        response.result = "[]";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    auto* exports = static_cast<Script::Module::ModuleExport*>(export_list.data);
    for (int i = 0; i < export_list.count; i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"ordinal\":" << exports[i].ordinal << ",";
        ss << "\"rva\":\"" << format_address(exports[i].rva) << "\",";
        ss << "\"va\":\"" << format_address(exports[i].va) << "\",";
        ss << "\"forwarded\":" << (exports[i].forwarded ? "true" : "false") << ",";
        ss << "\"forwardName\":\"" << escape_json(exports[i].forwardName) << "\",";
        ss << "\"name\":\"" << escape_json(exports[i].name) << "\",";
        ss << "\"undecoratedName\":\"" << escape_json(exports[i].undecoratedName) << "\"";
        ss << "}";
    }

    ss << "]";

    if (export_list.data) {
        BridgeFree(export_list.data);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mod_imports(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());
    if (!base) {
        response.success = false;
        response.error = "Module not found";
        return response;
    }

    Script::Module::ModuleInfo modInfo = {};
    if (!Script::Module::InfoFromAddr(base, &modInfo)) {
        response.success = false;
        response.error = "Failed to get module info";
        return response;
    }

    ListInfo import_list = {};
    if (!Script::Module::GetImports(&modInfo, &import_list)) {
        response.success = true;
        response.result = "[]";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    auto* imports = static_cast<Script::Module::ModuleImport*>(import_list.data);
    for (int i = 0; i < import_list.count; i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"iatRva\":\"" << format_address(imports[i].iatRva) << "\",";
        ss << "\"iatVa\":\"" << format_address(imports[i].iatVa) << "\",";
        ss << "\"ordinal\":" << imports[i].ordinal << ",";
        ss << "\"name\":\"" << escape_json(imports[i].name) << "\",";
        ss << "\"undecoratedName\":\"" << escape_json(imports[i].undecoratedName) << "\"";
        ss << "}";
    }

    ss << "]";

    if (import_list.data) {
        BridgeFree(import_list.data);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_disasm(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t count_pos = msg.params.find("\"count\"");

    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    int count = 10;
    if (count_pos != std::string::npos) {
        start = count_pos + 7;
        while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
        end = start;
        while (end < msg.params.length() && isdigit(msg.params[end])) end++;
        if (end > start) {
            count = std::stoi(msg.params.substr(start, end - start));
        }
    }

    std::ostringstream ss;
    ss << "[";

    duint current = static_cast<duint>(address);
    for (int i = 0; i < count; i++) {
        DISASM_INSTR instr;
        DbgDisasmAt(current, &instr);
        if (instr.instr_size == 0) {
            break;
        }

        std::ostringstream bytes_ss;
        std::vector<uint8_t> instr_bytes(instr.instr_size);
        if (DbgMemRead(current, instr_bytes.data(), instr.instr_size)) {
            for (int b = 0; b < instr.instr_size; b++) {
                bytes_ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(instr_bytes[b]);
            }
        }

        char comment_buf[256];
        comment_buf[0] = 0;
        DbgGetCommentAt(current, comment_buf);

        char label_buf[256];
        label_buf[0] = 0;
        DbgGetLabelAt(current, SEG_DEFAULT, label_buf);

        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"address\":\"" << format_address(current) << "\",";
        ss << "\"instruction\":\"" << escape_json(instr.instruction) << "\",";
        ss << "\"size\":" << instr.instr_size << ",";
        ss << "\"bytes\":\"" << bytes_ss.str() << "\",";
        ss << "\"comment\":\"" << escape_json(comment_buf) << "\",";
        ss << "\"label\":\"" << escape_json(label_buf) << "\"";
        ss << "}";

        current += instr.instr_size;
    }

    ss << "]";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_assemble(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t instr_pos = msg.params.find("\"instruction\"");

    if (addr_pos == std::string::npos || instr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' or 'instruction' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    start = msg.params.find('"', instr_pos + 13);
    if (start != std::string::npos) start++;
    end = msg.params.find('"', start);
    std::string instruction = msg.params.substr(start, end - start);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "asm %s, \"%s\"", addr_str.c_str(), instruction.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_goto(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "disasm %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_status(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    std::ostringstream ss;
    ss << "{";
    ss << "\"debugging\":" << (g_state.debugging ? "true" : "false") << ",";
    ss << "\"paused\":" << (g_state.paused ? "true" : "false") << ",";
    ss << "\"initialized\":" << (g_state.initialized ? "true" : "false");
    ss << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_ping(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;
    response.success = true;
    response.result = "\"pong\"";
    return response;
}

PipeResponse CommandHandler::cmd_lbl_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    ListInfo label_list = {};
    if (!Script::Label::GetList(&label_list)) {
        response.success = true;
        response.result = "[]";
        return response;
    }

    auto* labels = static_cast<Script::Label::LabelInfo*>(label_list.data);

    uint64_t range_start = 0;
    uint64_t range_end = UINT64_MAX;

    size_t sp = msg.params.find("\"start\"");
    if (sp != std::string::npos) {
        size_t vs = sp + 7;
        while (vs < msg.params.length() && !isdigit(msg.params[vs])) vs++;
        size_t ve = vs;
        while (ve < msg.params.length() && isdigit(msg.params[ve])) ve++;
        if (ve > vs) {
            try { range_start = std::stoull(msg.params.substr(vs, ve - vs)); }
            catch (const std::exception&) {}
        }
    }
    size_t ep = msg.params.find("\"end\"");
    if (ep != std::string::npos) {
        size_t vs = ep + 5;
        while (vs < msg.params.length() && !isdigit(msg.params[vs])) vs++;
        size_t ve = vs;
        while (ve < msg.params.length() && isdigit(msg.params[ve])) ve++;
        if (ve > vs) {
            try { range_end = std::stoull(msg.params.substr(vs, ve - vs)); }
            catch (const std::exception&) {}
        }
    }

    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (int i = 0; i < label_list.count; i++) {
        duint base = Script::Module::BaseFromName(labels[i].mod);
        duint addr = base + labels[i].rva;
        if (addr < range_start || addr > range_end) continue;
        if (!first) ss << ",";
        first = false;
        ss << "{\"address\":\"" << format_address(addr) << "\","
           << "\"text\":\"" << escape_json(labels[i].text) << "\","
           << "\"module\":\"" << escape_json(labels[i].mod) << "\""
           << "}";
    }
    ss << "]";

    if (label_list.data) BridgeFree(label_list.data);

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_cmt_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    ListInfo comment_list = {};
    if (!Script::Comment::GetList(&comment_list)) {
        response.success = true;
        response.result = "[]";
        return response;
    }

    auto* comments = static_cast<Script::Comment::CommentInfo*>(comment_list.data);

    uint64_t range_start = 0;
    uint64_t range_end = UINT64_MAX;

    size_t sp = msg.params.find("\"start\"");
    if (sp != std::string::npos) {
        size_t vs = sp + 7;
        while (vs < msg.params.length() && !isdigit(msg.params[vs])) vs++;
        size_t ve = vs;
        while (ve < msg.params.length() && isdigit(msg.params[ve])) ve++;
        if (ve > vs) {
            try { range_start = std::stoull(msg.params.substr(vs, ve - vs)); }
            catch (const std::exception&) {}
        }
    }
    size_t ep = msg.params.find("\"end\"");
    if (ep != std::string::npos) {
        size_t vs = ep + 5;
        while (vs < msg.params.length() && !isdigit(msg.params[vs])) vs++;
        size_t ve = vs;
        while (ve < msg.params.length() && isdigit(msg.params[ve])) ve++;
        if (ve > vs) {
            try { range_end = std::stoull(msg.params.substr(vs, ve - vs)); }
            catch (const std::exception&) {}
        }
    }

    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (int i = 0; i < comment_list.count; i++) {
        duint base = Script::Module::BaseFromName(comments[i].mod);
        duint addr = base + comments[i].rva;
        if (addr < range_start || addr > range_end) continue;
        if (!first) ss << ",";
        first = false;
        ss << "{\"address\":\"" << format_address(addr) << "\","
           << "\"text\":\"" << escape_json(comments[i].text) << "\","
           << "\"module\":\"" << escape_json(comments[i].mod) << "\""
           << "}";
    }
    ss << "]";

    if (comment_list.data) BridgeFree(comment_list.data);

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_stack_trace(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DBGCALLSTACK callstack = {};
    DbgFunctions()->GetCallStack(&callstack);

    std::ostringstream ss;
    ss << "[";
    for (int i = 0; i < callstack.total; i++) {
        if (i > 0) ss << ",";
        ss << "{\"index\":" << i << ","
           << "\"address\":\"" << format_address(callstack.entries[i].addr) << "\","
           << "\"from\":\"" << format_address(callstack.entries[i].from) << "\","
           << "\"to\":\"" << format_address(callstack.entries[i].to) << "\","
           << "\"comment\":\"" << escape_json(callstack.entries[i].comment) << "\""
           << "}";
    }
    ss << "]";

    if (callstack.entries) BridgeFree(callstack.entries);

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_eval(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t expr_pos = msg.params.find("\"expression\"");
    if (expr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'expression' parameter";
        return response;
    }

    size_t start = msg.params.find('"', expr_pos + 12);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string expr = msg.params.substr(start, end - start);

    duint value = DbgValFromString(expr.c_str());

    response.success = true;
    response.result = "\"" + format_address(value) + "\"";
    return response;
}

PipeResponse CommandHandler::cmd_ref_search(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "reffind %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_cfg(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    int max_blocks = 500;
    size_t mb_pos = msg.params.find("\"max_blocks\"");
    if (mb_pos != std::string::npos) {
        start = mb_pos + 12;
        while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
        end = start;
        while (end < msg.params.length() && isdigit(msg.params[end])) end++;
        if (end > start) max_blocks = std::stoi(msg.params.substr(start, end - start));
    }

    std::set<uint64_t> visited;
    std::vector<uint64_t> worklist;
    worklist.push_back(address);

    std::ostringstream blocks_ss;
    std::ostringstream edges_ss;
    blocks_ss << "[";
    edges_ss << "[";
    int block_count = 0;
    bool first_block = true;
    bool first_edge = true;

    while (!worklist.empty() && block_count < max_blocks) {
        uint64_t block_start = worklist.back();
        worklist.pop_back();

        if (visited.count(block_start)) continue;
        visited.insert(block_start);

        duint current = static_cast<duint>(block_start);
        int instr_count = 0;
        duint block_end = current;

        for (int i = 0; i < 1000; i++) {
            DISASM_INSTR instr;
            DbgDisasmAt(current, &instr);
            if (instr.instr_size == 0) break;
            instr_count++;
            block_end = current + instr.instr_size;

            BASIC_INSTRUCTION_INFO info;
            DbgDisasmFastAt(current, &info);

            if (info.branch) {
                duint dest = DbgGetBranchDestination(current);
                if (dest != 0) {
                    if (!first_edge) edges_ss << ",";
                    first_edge = false;
                    edges_ss << "{\"from\":\"" << format_address(current) << "\",\"to\":\"" << format_address(dest) << "\"}";
                    if (!visited.count(dest)) worklist.push_back(dest);
                }
                if (!info.call) {
                    if (info.type != 0) {
                        duint fallthrough = current + instr.instr_size;
                        if (!first_edge) edges_ss << ",";
                        first_edge = false;
                        edges_ss << "{\"from\":\"" << format_address(current) << "\",\"to\":\"" << format_address(fallthrough) << "\"}";
                        if (!visited.count(fallthrough)) worklist.push_back(fallthrough);
                    }
                    break;
                }
            }

            if (std::string(instr.instruction).find("ret") != std::string::npos) break;
            current += instr.instr_size;
        }

        if (!first_block) blocks_ss << ",";
        first_block = false;
        blocks_ss << "{\"start\":\"" << format_address(block_start) << "\","
                  << "\"end\":\"" << format_address(block_end) << "\","
                  << "\"instructions\":" << instr_count << "}";
        block_count++;
    }

    blocks_ss << "]";
    edges_ss << "]";

    std::ostringstream ss;
    ss << "{\"entry\":\"" << format_address(address) << "\","
       << "\"blocks\":" << blocks_ss.str() << ","
       << "\"edges\":" << edges_ss.str() << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_patch_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t buf_size = 0;
    DbgFunctions()->PatchEnum(nullptr, &buf_size);

    std::ostringstream ss;
    ss << "[";

    if (buf_size > 0) {
        std::vector<DBGPATCHINFO> patches(buf_size / sizeof(DBGPATCHINFO));
        DbgFunctions()->PatchEnum(patches.data(), &buf_size);

        for (size_t i = 0; i < patches.size(); i++) {
            if (i > 0) ss << ",";
            ss << "{\"address\":\"" << format_address(patches[i].addr) << "\","
               << "\"oldByte\":" << static_cast<int>(patches[i].oldbyte) << ","
               << "\"newByte\":" << static_cast<int>(patches[i].newbyte) << "}";
        }
    }

    ss << "]";
    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_patch_restore(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    bool result = DbgFunctions()->PatchRestore(static_cast<duint>(address));
    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_seh_chain(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    duint teb = DbgValFromString("teb()");
    if (teb == 0) {
        response.success = false;
        response.error = "Failed to get TEB address";
        return response;
    }

    duint exception_list = 0;
    if (!DbgMemRead(teb, &exception_list, sizeof(duint))) {
        response.success = false;
        response.error = "Failed to read ExceptionList from TEB";
        return response;
    }

    std::ostringstream ss;
    ss << "[";
    int index = 0;
    duint current = exception_list;
    bool first = true;

    while (current != 0 && current != static_cast<duint>(-1) && index < 64) {
        duint next = 0, handler = 0;
        if (!DbgMemRead(current, &next, sizeof(duint))) break;
        if (!DbgMemRead(current + sizeof(duint), &handler, sizeof(duint))) break;

        if (!first) ss << ",";
        first = false;
        ss << "{\"index\":" << index << ","
           << "\"address\":\"" << format_address(current) << "\","
           << "\"handler\":\"" << format_address(handler) << "\","
           << "\"next\":\"" << format_address(next) << "\"}";

        current = next;
        index++;
    }

    ss << "]";
    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_peb_read(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    duint peb = DbgValFromString("peb()");
    if (peb == 0) {
        response.success = false;
        response.error = "Failed to get PEB address";
        return response;
    }

    uint8_t being_debugged = 0;
    DbgMemRead(peb + 2, &being_debugged, 1);

    duint image_base = 0;
    DbgMemRead(peb + 0x10, &image_base, sizeof(duint));

    duint ldr = 0;
#ifdef BUILD_X64
    DbgMemRead(peb + 0x18, &ldr, sizeof(duint));
#else
    DbgMemRead(peb + 0x0C, &ldr, sizeof(duint));
#endif

    duint process_params = 0;
#ifdef BUILD_X64
    DbgMemRead(peb + 0x20, &process_params, sizeof(duint));
#else
    DbgMemRead(peb + 0x10, &process_params, sizeof(duint));
#endif

    uint32_t nt_global_flag = 0;
#ifdef BUILD_X64
    DbgMemRead(peb + 0xBC, &nt_global_flag, 4);
#else
    DbgMemRead(peb + 0x68, &nt_global_flag, 4);
#endif

    std::ostringstream ss;
    ss << "{\"address\":\"" << format_address(peb) << "\","
       << "\"beingDebugged\":" << static_cast<int>(being_debugged) << ","
       << "\"imageBaseAddress\":\"" << format_address(image_base) << "\","
       << "\"ldr\":\"" << format_address(ldr) << "\","
       << "\"processParameters\":\"" << format_address(process_params) << "\","
       << "\"ntGlobalFlag\":" << nt_global_flag << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_teb_read(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    duint teb = DbgValFromString("teb()");
    if (teb == 0) {
        response.success = false;
        response.error = "Failed to get TEB address";
        return response;
    }

    duint stack_base = 0, stack_limit = 0, self_ptr = 0;
    duint process_id = 0, thread_id = 0;

#ifdef BUILD_X64
    DbgMemRead(teb + 0x08, &stack_base, sizeof(duint));
    DbgMemRead(teb + 0x10, &stack_limit, sizeof(duint));
    DbgMemRead(teb + 0x30, &self_ptr, sizeof(duint));
    DbgMemRead(teb + 0x40, &process_id, sizeof(duint));
    DbgMemRead(teb + 0x48, &thread_id, sizeof(duint));
#else
    DbgMemRead(teb + 0x04, &stack_base, sizeof(duint));
    DbgMemRead(teb + 0x08, &stack_limit, sizeof(duint));
    DbgMemRead(teb + 0x18, &self_ptr, sizeof(duint));
    DbgMemRead(teb + 0x20, &process_id, sizeof(duint));
    DbgMemRead(teb + 0x24, &thread_id, sizeof(duint));
#endif

    std::ostringstream ss;
    ss << "{\"address\":\"" << format_address(teb) << "\","
       << "\"stackBase\":\"" << format_address(stack_base) << "\","
       << "\"stackLimit\":\"" << format_address(stack_limit) << "\","
       << "\"self\":\"" << format_address(self_ptr) << "\","
       << "\"processId\":" << process_id << ","
       << "\"threadId\":" << thread_id << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_pe_directories(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"module\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'module' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 8);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());
    if (!base) {
        response.success = false;
        response.error = "Module not found";
        return response;
    }

    uint8_t dos_hdr[64];
    if (!DbgMemRead(base, dos_hdr, 64)) {
        response.success = false;
        response.error = "Failed to read DOS header";
        return response;
    }

    uint32_t pe_offset = *reinterpret_cast<uint32_t*>(dos_hdr + 0x3C);
    uint8_t pe_hdr[512];
    if (!DbgMemRead(base + pe_offset, pe_hdr, 512)) {
        response.success = false;
        response.error = "Failed to read PE header";
        return response;
    }

    uint16_t machine = *reinterpret_cast<uint16_t*>(pe_hdr + 4);
    bool is_pe64 = (machine == 0x8664);
    int dir_offset = 24 + (is_pe64 ? 112 : 96);
    int num_dirs = *reinterpret_cast<uint32_t*>(pe_hdr + 24 + (is_pe64 ? 108 : 92));
    if (num_dirs > 16) num_dirs = 16;

    const char* dir_names[] = {
        "Export", "Import", "Resource", "Exception", "Security",
        "BaseReloc", "Debug", "Architecture", "GlobalPtr", "TLS",
        "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved"
    };

    std::ostringstream ss;
    ss << "[";
    for (int i = 0; i < num_dirs; i++) {
        int entry_offset = dir_offset + i * 8;
        if (entry_offset + 8 > 512) break;
        uint32_t rva = *reinterpret_cast<uint32_t*>(pe_hdr + entry_offset);
        uint32_t size = *reinterpret_cast<uint32_t*>(pe_hdr + entry_offset + 4);

        if (i > 0) ss << ",";
        ss << "{\"index\":" << i << ","
           << "\"name\":\"" << (i < 16 ? dir_names[i] : "Unknown") << "\","
           << "\"rva\":\"" << format_address(rva) << "\","
           << "\"size\":" << size << "}";
    }
    ss << "]";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_watch_add(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t expr_pos = msg.params.find("\"expression\"");
    if (expr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'expression' parameter";
        return response;
    }

    size_t start = msg.params.find('"', expr_pos + 12);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string expr = msg.params.substr(start, end - start);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "AddWatch \"%s\"", expr.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_watch_remove(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t idx_pos = msg.params.find("\"index\"");
    if (idx_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'index' parameter";
        return response;
    }

    size_t start = idx_pos + 7;
    while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
    size_t end = start;
    while (end < msg.params.length() && isdigit(msg.params[end])) end++;
    int index = std::stoi(msg.params.substr(start, end - start));

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "DelWatch %d", index);
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_watch_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;
    response.success = true;
    response.result = "[]";
    return response;
}

PipeResponse CommandHandler::cmd_trace_record(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    duint hit_count = DbgFunctions()->GetTraceRecordHitCount(static_cast<duint>(address));

    std::ostringstream ss;
    ss << "{\"address\":\"" << format_address(address) << "\","
       << "\"hitCount\":" << hit_count << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_plugin_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    bool result = DbgCmdExec("pluglist");
    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_thread_detail(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    THREADLIST threadList = {};
    DbgGetThreadList(&threadList);

    std::ostringstream ss;
    ss << "[";
    for (int i = 0; i < threadList.count; i++) {
        if (i > 0) ss << ",";
        ss << "{\"threadNumber\":" << threadList.list[i].BasicInfo.ThreadNumber << ","
           << "\"threadId\":" << threadList.list[i].BasicInfo.ThreadId << ","
           << "\"name\":\"" << escape_json(threadList.list[i].BasicInfo.threadName) << "\","
           << "\"rip\":\"" << format_address(threadList.list[i].BasicInfo.ThreadStartAddress) << "\","
           << "\"suspended\":" << (threadList.list[i].SuspendCount > 0 ? "true" : "false") << ","
           << "\"priority\":" << static_cast<int>(threadList.list[i].Priority)
           << "}";
    }
    ss << "]";

    if (threadList.list) BridgeFree(threadList.list);

    response.success = true;
    response.result = ss.str();
    return response;
}

uint64_t CommandHandler::parse_address(const std::string& addr_str) {
    if (addr_str.empty()) return 0;

    std::string clean = addr_str;
    if (clean.substr(0, 2) == "0x" || clean.substr(0, 2) == "0X") {
        clean = clean.substr(2);
    }

    try {
        return std::stoull(clean, nullptr, 16);
    } catch (const std::exception&) {
        return 0;
    }
}

std::string CommandHandler::format_address(uint64_t addr) {
    char buffer[32];
#ifdef BUILD_X64
    snprintf(buffer, sizeof(buffer), "0x%016llX", static_cast<unsigned long long>(addr));
#else
    snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<unsigned int>(addr));
#endif
    return std::string(buffer);
}

std::string CommandHandler::escape_json(const std::string& s) {
    std::ostringstream ss;
    for (char c : s) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    ss << "\\u" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(c);
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

}
