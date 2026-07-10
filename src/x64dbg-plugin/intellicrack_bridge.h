/**
 * @file intellicrack_bridge.h
 * @brief Intellicrack bridge plugin header for x64dbg/x32dbg
 *
 * Provides programmatic control of x64dbg through a named pipe server,
 * enabling Intellicrack to communicate with the debugger for automated
 * analysis and protection defeat operations.
 */

#ifndef INTELLICRACK_BRIDGE_H
#define INTELLICRACK_BRIDGE_H

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif

#include <cstdint>
#include <string>
#include <atomic>

#define PLUGIN_NAME "Intellicrack Bridge"
#define PLUGIN_VERSION 1

#ifdef BUILD_X64
#define PLUGIN_FILENAME "intellicrack_bridge_x64.dp64"
#else
#define PLUGIN_FILENAME "intellicrack_bridge_x32.dp32"
#endif

namespace intellicrack {

struct PluginState {
    bool initialized;
    bool pipe_server_running;
    HANDLE pipe_server_thread;
    bool stop_server;
    HANDLE stop_event;
    uint64_t current_address;
    uint64_t module_base;
    std::atomic<bool> debugging;
    std::atomic<bool> paused;
};

extern PluginState g_state;

bool initialize_plugin();
void shutdown_plugin();

void on_debug_event(int event_type, void* event_data);
void on_breakpoint_hit(uint64_t address);
void on_exception(uint32_t exception_code, uint64_t exception_address);
void on_dll_load(const char* dll_name, uint64_t base_address);
void on_dll_unload(const char* dll_name, uint64_t base_address);
void on_process_start(const char* exe_path, uint32_t pid);
void on_process_exit(uint32_t exit_code);
void on_paused(uint64_t address);
void on_resumed();

}

#endif
