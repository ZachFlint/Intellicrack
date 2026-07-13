/**
 * @file intellicrack_bridge.cpp
 * @brief Main plugin entry point for Intellicrack x64dbg bridge
 *
 * Implements the x64dbg plugin interface and initializes the named pipe
 * server for communication with Intellicrack.
 */

#include "intellicrack_bridge.h"
#include "pipe_server.h"
#include "command_handler.h"

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
#include <pluginsdk/bridgemain.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cstdio>
#include <cstring>
#include <sstream>

namespace {

std::string escape_json_path(const char* s) {
    std::ostringstream ss;
    if (!s) return "unknown";
    for (const char* p = s; *p; ++p) {
        switch (*p) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(*p) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<int>(*p));
                    ss << buf;
                } else {
                    ss << *p;
                }
        }
    }
    return ss.str();
}

// Passed to the EnumWindows callback so it can tell x64dbg's main window
// (hidden to keep the debugger alive) from auxiliary popups (closed), and
// report back how much window activity a sweep pass observed.
struct HeadlessSweepCtx {
    DWORD pid{0};
    HWND main_window{nullptr};
    int acted{0};  // number of windows hidden/closed on this pass
};

BOOL CALLBACK headless_sweep_window(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<HeadlessSweepCtx*>(lparam);
    DWORD win_pid = 0;
    GetWindowThreadProcessId(hwnd, &win_pid);
    if (win_pid != ctx->pid || !IsWindowVisible(hwnd)) {
        return TRUE;
    }

    if (hwnd == ctx->main_window) {
        // The main debugger window: hide it so x64dbg keeps running as a
        // windowless engine driven over the pipe.
        ShowWindow(hwnd, SW_HIDE);
    } else {
        // An auxiliary popup (notably the version "Release Notes" dialog):
        // close it so its modal message loop unwinds cleanly. Hiding such a
        // dialog with SW_HIDE would leave the loop spinning and wedge the
        // GUI thread, stalling command dispatch.
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    }
    ctx->acted++;
    return TRUE;
}

DWORD WINAPI headless_sweep_thread(LPVOID) {
    // The main window and the startup "Release Notes" popup each appear a
    // beat apart from plugin setup, so sweep for a minimum window to catch
    // them, then stop as soon as the debugger has settled with nothing left
    // to hide or close. Terminating promptly keeps this background thread
    // from contending with debugger command dispatch during a session.
    const int MIN_PASSES = 15;   // ~3.0s minimum coverage for late popups
    const int MAX_PASSES = 80;   // ~16s hard ceiling
    const int SETTLE_PASSES = 4; // consecutive idle passes before stopping
    const DWORD INTERVAL_MS = 200;

    int settled = 0;
    for (int i = 0; i < MAX_PASSES; ++i) {
        HWND main_window = GuiGetWindowHandle();
        HeadlessSweepCtx ctx{ GetCurrentProcessId(), main_window, 0 };
        if (main_window) {
            EnumWindows(headless_sweep_window, reinterpret_cast<LPARAM>(&ctx));
        }

        settled = (main_window && ctx.acted == 0) ? settled + 1 : 0;
        if (i >= MIN_PASSES && settled >= SETTLE_PASSES) {
            break;
        }
        Sleep(INTERVAL_MS);
    }
    return 0;
}

// When Intellicrack launches x64dbg as an embedded, headless debugging
// engine it exports INTELLICRACK_X64DBG_HEADLESS=1 so the debugger runs
// windowless and every interaction happens through the Intellicrack x64dbg
// panel over the named pipe. A background sweep hides the main window and
// dismisses auxiliary popups so no debugger window is ever presented. A
// standalone x64dbg launch (no such variable) is left untouched.
void hide_windows_if_headless() {
    char buf[8] = {};
    DWORD n = GetEnvironmentVariableA("INTELLICRACK_X64DBG_HEADLESS", buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf) || buf[0] != '1') {
        return;
    }

    HANDLE thread = CreateThread(nullptr, 0, headless_sweep_thread, nullptr, 0, nullptr);
    if (thread) {
        CloseHandle(thread);
    }
}

}

namespace intellicrack {

PluginState g_state = {};

static int plugin_handle = -1;
static int menu_handle = -1;

bool initialize_plugin() {
    g_state.initialized = false;
    g_state.pipe_server_running = false;
    g_state.stop_server = false;
    g_state.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_state.current_address = 0;
    g_state.module_base = 0;
    g_state.debugging = false;
    g_state.paused = false;

    g_pipe_server.set_command_handler([](const PipeMessage& msg) -> PipeResponse {
        return g_command_handler.handle_command(msg);
    });

    if (!g_pipe_server.start()) {
        _plugin_logputs("[Intellicrack] Failed to start pipe server");
        return false;
    }

    g_state.pipe_server_running = true;
    g_state.initialized = true;
    _plugin_logputs("[Intellicrack] Bridge plugin initialized - pipe server running");
    return true;
}

void shutdown_plugin() {
    if (g_state.stop_event) {
        SetEvent(g_state.stop_event);
    }

    g_pipe_server.stop();
    g_state.pipe_server_running = false;

    if (g_state.stop_event) {
        CloseHandle(g_state.stop_event);
        g_state.stop_event = nullptr;
    }

    g_state.initialized = false;
    _plugin_logputs("[Intellicrack] Bridge plugin shutdown");
}

void on_debug_event(int event_type, void* event_data) {
    (void)event_type;
    (void)event_data;
}

void on_breakpoint_hit(uint64_t address) {
    if (!g_state.pipe_server_running) return;

    char event_json[256];
    snprintf(event_json, sizeof(event_json),
        R"({"type":"event","event":"breakpoint","address":"0x%llX"})",
        static_cast<unsigned long long>(address));
    g_pipe_server.broadcast_event(event_json);
}

void on_exception(uint32_t exception_code, uint64_t exception_address) {
    if (!g_state.pipe_server_running) return;

    char event_json[256];
    snprintf(event_json, sizeof(event_json),
        R"({"type":"event","event":"exception","code":"0x%X","address":"0x%llX"})",
        exception_code, static_cast<unsigned long long>(exception_address));
    g_pipe_server.broadcast_event(event_json);
}

void on_dll_load(const char* dll_name, uint64_t base_address) {
    if (!g_state.pipe_server_running) return;

    std::ostringstream ss;
    ss << R"({"type":"event","event":"dll_load","name":")"
       << escape_json_path(dll_name)
       << R"(","base":"0x)" << std::hex << std::uppercase << base_address
       << R"("})";
    g_pipe_server.broadcast_event(ss.str());
}

void on_dll_unload(const char* dll_name, uint64_t base_address) {
    if (!g_state.pipe_server_running) return;

    std::ostringstream ss;
    ss << R"({"type":"event","event":"dll_unload","name":")"
       << escape_json_path(dll_name)
       << R"(","base":"0x)" << std::hex << std::uppercase << base_address
       << R"("})";
    g_pipe_server.broadcast_event(ss.str());
}

void on_process_start(const char* exe_path, uint32_t pid) {
    if (!g_state.pipe_server_running) return;

    g_state.debugging = true;
    g_state.paused = true;

    std::ostringstream ss;
    ss << R"({"type":"event","event":"process_start","path":")"
       << escape_json_path(exe_path)
       << R"(","pid":)" << pid << '}';
    g_pipe_server.broadcast_event(ss.str());
}

void on_process_exit(uint32_t exit_code) {
    if (!g_state.pipe_server_running) return;

    g_state.debugging = false;
    g_state.paused = false;

    char event_json[128];
    snprintf(event_json, sizeof(event_json),
        R"({"type":"event","event":"process_exit","exit_code":%u})",
        exit_code);
    g_pipe_server.broadcast_event(event_json);
}

void on_paused(uint64_t address) {
    // Broadcast a "paused" event whenever x64dbg suspends the debuggee
    // (after a step, after explicit pause, after an unhandled exception
    // routed through the breakpoint manager). The Intellicrack bridge
    // awaits this event after issuing step_into/step_over/step_out so it
    // can read registers only once the IP has actually moved (audit6.md
    // F-0004).
    if (!g_state.pipe_server_running) return;

    char event_json[256];
    snprintf(event_json, sizeof(event_json),
        R"({"type":"event","event":"paused","address":"0x%llX"})",
        static_cast<unsigned long long>(address));
    g_pipe_server.broadcast_event(event_json);
}

void on_resumed() {
    if (!g_state.pipe_server_running) return;

    g_pipe_server.broadcast_event(R"({"type":"event","event":"resumed"})");
}

}


extern "C" {

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    intellicrack::plugin_handle = initStruct->pluginHandle;

    return true;
}

DLL_EXPORT bool plugstop() {
    intellicrack::shutdown_plugin();
    return true;
}

DLL_EXPORT void plugsetup(const PLUG_SETUPSTRUCT* setupStruct) {
    intellicrack::menu_handle = setupStruct->hMenu;

    _plugin_menuaddentry(intellicrack::menu_handle, 0, "About Intellicrack Bridge...");
    _plugin_menuaddentry(intellicrack::menu_handle, 1, "Restart Pipe Server");
    _plugin_menuaddseparator(intellicrack::menu_handle);
    _plugin_menuaddentry(intellicrack::menu_handle, 2, "Server Status");

    if (!intellicrack::initialize_plugin()) {
        _plugin_logputs("[Intellicrack] Plugin initialization failed!");
    }

    hide_windows_if_headless();
}

DLL_EXPORT void CBMENUENTRY(CBTYPE cbType, const PLUG_CB_MENUENTRY* info) {
    (void)cbType;

    switch (info->hEntry) {
    case 0:
        MessageBoxA(
            GuiGetWindowHandle(),
            "Intellicrack Bridge Plugin v1.0\n\n"
            "Provides named pipe IPC for Intellicrack integration.\n"
            "Pipe: \\\\.\\pipe\\intellicrack_x64dbg",
            "About Intellicrack Bridge",
            MB_ICONINFORMATION
        );
        break;

    case 1:
        intellicrack::g_pipe_server.stop();
        if (intellicrack::g_pipe_server.start()) {
            _plugin_logputs("[Intellicrack] Pipe server restarted");
        } else {
            _plugin_logputs("[Intellicrack] Failed to restart pipe server");
        }
        break;

    case 2: {
        const char* status = intellicrack::g_pipe_server.is_running()
            ? "Pipe server: RUNNING"
            : "Pipe server: STOPPED";
        _plugin_logputs(status);
        break;
    }
    default:
        break;
    }
}

DLL_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info) {
    (void)cbType;
    if (info && info->fdProcessInfo) {
        intellicrack::on_process_start(
            info->DebugFileName ? info->DebugFileName : nullptr,
            info->fdProcessInfo->dwProcessId
        );
    }
}

DLL_EXPORT void CBEXITPROCESS(CBTYPE cbType, const PLUG_CB_EXITPROCESS* info) {
    (void)cbType;
    intellicrack::on_process_exit(
        info && info->ExitProcess ? info->ExitProcess->dwExitCode : 0
    );
}

DLL_EXPORT void CBLOADDLL(CBTYPE cbType, PLUG_CB_LOADDLL* info) {
    (void)cbType;
    if (info && info->modInfo) {
        intellicrack::on_dll_load(
            info->modname ? info->modname : "unknown",
            static_cast<uint64_t>(info->modInfo->BaseOfImage)
        );
    }
}

DLL_EXPORT void CBUNLOADDLL(CBTYPE cbType, const PLUG_CB_UNLOADDLL* info) {
    (void)cbType;
    if (info && info->UnloadDll) {
        intellicrack::on_dll_unload(
            nullptr,
            reinterpret_cast<uint64_t>(info->UnloadDll->lpBaseOfDll)
        );
    }
}

DLL_EXPORT void CBBREAKPOINT(CBTYPE cbType, const PLUG_CB_BREAKPOINT* info) {
    (void)cbType;
    if (info && info->breakpoint) {
        intellicrack::g_state.paused = true;
        intellicrack::on_breakpoint_hit(info->breakpoint->addr);
    }
}

DLL_EXPORT void CBEXCEPTION(CBTYPE cbType, const PLUG_CB_EXCEPTION* info) {
    (void)cbType;
    if (info && info->Exception) {
        intellicrack::on_exception(
            info->Exception->ExceptionRecord.ExceptionCode,
            reinterpret_cast<uint64_t>(info->Exception->ExceptionRecord.ExceptionAddress)
        );
    }
}

DLL_EXPORT void CBPAUSEDEBUG(CBTYPE cbType, void* info) {
    (void)cbType;
    (void)info;
    intellicrack::g_state.paused = true;
    duint cip = Script::Register::GetCIP();
    intellicrack::on_paused(static_cast<uint64_t>(cip));
}

DLL_EXPORT void CBRESUMEDEBUG(CBTYPE cbType, void* info) {
    (void)cbType;
    (void)info;
    intellicrack::g_state.paused = false;
    intellicrack::on_resumed();
}

DLL_EXPORT void CBSTOPDEBUG(CBTYPE cbType, void* info) {
    (void)cbType;
    (void)info;
    intellicrack::g_state.debugging = false;
    intellicrack::g_state.paused = false;
}

}
