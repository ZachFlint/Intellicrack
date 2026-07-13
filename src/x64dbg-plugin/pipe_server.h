/**
 * @file pipe_server.h
 * @brief Named pipe server for Intellicrack IPC
 *
 * Implements a Windows named pipe server that listens for commands
 * from Intellicrack and sends events/responses back.
 */

#ifndef INTELLICRACK_PIPE_SERVER_H
#define INTELLICRACK_PIPE_SERVER_H

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <cstdint>
#include <string>
#include <functional>
#include <mutex>
#include <vector>
#include <atomic>

namespace intellicrack {

constexpr const char* PIPE_NAME = "\\\\.\\pipe\\intellicrack_x64dbg";
constexpr DWORD PIPE_BUFFER_SIZE = 65536;
constexpr DWORD READ_TIMEOUT_MS = 100;
constexpr DWORD CONNECT_TIMEOUT_MS = 5000;
constexpr DWORD PAYLOAD_READ_TIMEOUT_MS = 30000;

struct PipeMessage {
    uint32_t id{0};
    std::string type;
    std::string command;
    std::string params;
    std::string raw_json;
};

struct PipeResponse {
    uint32_t id{0};
    bool success{false};
    std::string result;
    std::string error;
};

using PipeCommandHandler = std::function<PipeResponse(const PipeMessage&)>;

class PipeServer {
public:
    PipeServer();
    ~PipeServer();

    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;
    PipeServer(PipeServer&&) = delete;
    PipeServer& operator=(PipeServer&&) = delete;

    bool start();
    void stop();
    bool is_running() const;

    void set_command_handler(PipeCommandHandler handler);

    bool send_event(const std::string& event_type, const std::string& data);
    bool broadcast_event(const std::string& event_json);

private:
    HANDLE m_pipe_handle;
    HANDLE m_server_thread;
    HANDLE m_stop_event;
    std::atomic<bool> m_running;
    std::atomic<bool> m_client_connected;
    std::mutex m_pipe_mutex;
    PipeCommandHandler m_command_handler;

    static DWORD WINAPI server_thread_proc(LPVOID param);
    void server_loop();
    bool create_pipe_instance();
    bool wait_for_client();
    void handle_client();
    bool read_message(PipeMessage& msg);
    bool write_response(const PipeResponse& response);
    bool write_message(const char* payload, uint32_t length);
    bool write_data_locked(const char* data, uint32_t length);
    bool read_data(char* buffer, uint32_t length, DWORD timeout_ms);
    static std::string serialize_response(const PipeResponse& response);
    static bool parse_message(const std::string& json, PipeMessage& msg);
};

extern PipeServer g_pipe_server;

}

#endif
