#include "command_handler.h"
#include "event_handler.h"
#include "pipe_server.h"

#include <cstdint>
#include <memory>

#include "plugin.h"

namespace {

std::unique_ptr<intellicrack::PipeServer> g_server;
intellicrack::CommandHandler g_handler;
intellicrack::EventHandler g_event_handler;
int g_plugin_handle = 0;

void cb_breakpoint(CBTYPE, PLUG_CB_BREAKPOINT* info) {
    if (info == nullptr) {
        return;
    }
    g_event_handler.send_breakpoint(static_cast<std::uint64_t>(info->addr));
}

void cb_memory_breakpoint(CBTYPE, PLUG_CB_MEMORYBREAKPOINT* info) {
    if (info == nullptr) {
        return;
    }
    g_event_handler.send_watchpoint(static_cast<std::uint64_t>(info->addr));
}

}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    if (initStruct == nullptr) {
        return false;
    }
    g_plugin_handle = initStruct->pluginHandle;
    g_server = std::make_unique<intellicrack::PipeServer>(
        [](const nlohmann::json& request) { return g_handler.handle(request); });
    g_event_handler.set_server(g_server.get());
    g_server->start();

    _plugin_registercallback(g_plugin_handle, CB_BREAKPOINT, reinterpret_cast<CBPLUGIN>(cb_breakpoint));
    _plugin_registercallback(g_plugin_handle, CB_MEMORYBREAKPOINT, reinterpret_cast<CBPLUGIN>(cb_memory_breakpoint));

    return true;
}

PLUG_EXPORT bool plugstop() {
    if (g_server) {
        g_server->stop();
        g_server.reset();
    }
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT*) {}
