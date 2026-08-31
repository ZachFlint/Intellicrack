/**
 * @file pipe_server.cpp
 * @brief Named pipe server implementation for Intellicrack IPC
 */

#include "pipe_server.h"
#include <cstring>
#include <cstdio>
#include <sstream>

namespace intellicrack {

PipeServer g_pipe_server;

PipeServer::PipeServer()
    : m_pipe_handle(INVALID_HANDLE_VALUE)
    , m_server_thread(nullptr)
    , m_stop_event(nullptr)
    , m_running(false)
    , m_client_connected(false)
    , m_command_handler(nullptr) {
}

PipeServer::~PipeServer() {
    stop();
}

bool PipeServer::start() {
    if (m_running.load()) {
        return true;
    }

    m_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_stop_event) {
        return false;
    }

    m_running.store(true);
    m_server_thread = CreateThread(
        nullptr,
        0,
        server_thread_proc,
        this,
        0,
        nullptr
    );

    if (!m_server_thread) {
        CloseHandle(m_stop_event);
        m_stop_event = nullptr;
        m_running.store(false);
        return false;
    }

    return true;
}

void PipeServer::stop() {
    if (!m_running.load()) {
        return;
    }

    m_running.store(false);

    if (m_stop_event) {
        SetEvent(m_stop_event);
    }

    if (m_server_thread) {
        WaitForSingleObject(m_server_thread, 5000);
        CloseHandle(m_server_thread);
        m_server_thread = nullptr;
    }

    if (m_stop_event) {
        CloseHandle(m_stop_event);
        m_stop_event = nullptr;
    }

    m_client_connected.store(false);
}

bool PipeServer::is_running() const {
    return m_running.load();
}

void PipeServer::set_command_handler(PipeCommandHandler handler) {
    m_command_handler = std::move(handler);
}

DWORD WINAPI PipeServer::server_thread_proc(LPVOID param) {
    auto* server = static_cast<PipeServer*>(param);
    server->server_loop();
    return 0;
}

void PipeServer::server_loop() {
    while (m_running.load()) {
        if (!create_pipe_instance()) {
            Sleep(1000);
            continue;
        }

        if (wait_for_client()) {
            m_client_connected.store(true);
            handle_client();
            m_client_connected.store(false);
        }

        {
            std::lock_guard<std::mutex> lock(m_pipe_mutex);
            if (m_pipe_handle != INVALID_HANDLE_VALUE) {
                DisconnectNamedPipe(m_pipe_handle);
                CloseHandle(m_pipe_handle);
                m_pipe_handle = INVALID_HANDLE_VALUE;
            }
        }
    }
}

bool PipeServer::create_pipe_instance() {
    std::lock_guard<std::mutex> lock(m_pipe_mutex);

    m_pipe_handle = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        nullptr
    );

    return m_pipe_handle != INVALID_HANDLE_VALUE;
}

bool PipeServer::wait_for_client() {
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) {
        return false;
    }

    BOOL connected = ConnectNamedPipe(m_pipe_handle, &overlapped);
    if (!connected) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            HANDLE wait_handles[2] = { overlapped.hEvent, m_stop_event };
            DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);

            CloseHandle(overlapped.hEvent);

            if (wait_result == WAIT_OBJECT_0 + 1) {
                return false;
            }

            return wait_result == WAIT_OBJECT_0;
        } else if (error == ERROR_PIPE_CONNECTED) {
            CloseHandle(overlapped.hEvent);
            return true;
        }

        CloseHandle(overlapped.hEvent);
        return false;
    }

    CloseHandle(overlapped.hEvent);
    return true;
}

void PipeServer::handle_client() {
    while (m_running.load() && m_client_connected.load()) {
        PipeMessage msg;
        if (!read_message(msg)) {
            break;
        }

        PipeResponse response;
        response.id = msg.id;
        response.success = false;
        response.error = "No handler";

        if (m_command_handler) {
            response = m_command_handler(msg);
        }

        if (!write_response(response)) {
            break;
        }
    }
}

bool PipeServer::read_message(PipeMessage& msg) {
    uint32_t length = 0;
    // Wait indefinitely for the next command frame's length prefix. A
    // connected client legitimately sits idle between commands, and a
    // running debuggee can take arbitrarily long to reach a breakpoint,
    // so bounding this idle read would tear down a healthy client and
    // silently drop every subsequent breakpoint/pause event. The wait is
    // still interruptible by the stop event and by client disconnect
    // (ReadFile completes with a broken-pipe error).
    if (!read_data(reinterpret_cast<char*>(&length), sizeof(length), INFINITE)) {
        return false;
    }

    if (length == 0 || length > PIPE_BUFFER_SIZE) {
        return false;
    }

    // Once a frame has started, its payload has already been written by the
    // client under its write lock, so bound the continuation read to guard
    // against a half-sent frame from a buggy peer.
    std::vector<char> buffer(length + 1);
    if (!read_data(buffer.data(), length, PAYLOAD_READ_TIMEOUT_MS)) {
        return false;
    }
    buffer[length] = '\0';

    msg.raw_json = std::string(buffer.data(), length);
    return parse_message(msg.raw_json, msg);
}

bool PipeServer::write_response(const PipeResponse& response) {
    std::string json = serialize_response(response);
    return write_message(json.c_str(), static_cast<uint32_t>(json.size()));
}

bool PipeServer::write_message(const char* payload, uint32_t length) {
    // Frame the length prefix and payload under a single lock so an
    // asynchronous event broadcast (issued from an x64dbg debug-event
    // callback thread) can never interleave its bytes between another
    // message's length prefix and body on the byte-stream pipe.
    std::lock_guard<std::mutex> lock(m_pipe_mutex);

    if (!write_data_locked(reinterpret_cast<const char*>(&length), sizeof(length))) {
        return false;
    }

    return write_data_locked(payload, length);
}

bool PipeServer::write_data_locked(const char* data, uint32_t length) {
    if (m_pipe_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) {
        return false;
    }

    DWORD bytes_written = 0;
    BOOL result = WriteFile(m_pipe_handle, data, length, &bytes_written, &overlapped);

    if (!result) {
        if (GetLastError() == ERROR_IO_PENDING) {
            HANDLE wait_handles[2] = { overlapped.hEvent, m_stop_event };
            DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, 5000);

            if (wait_result == WAIT_OBJECT_0) {
                GetOverlappedResult(m_pipe_handle, &overlapped, &bytes_written, FALSE);
                CloseHandle(overlapped.hEvent);
                return bytes_written == length;
            }

            CancelIo(m_pipe_handle);
            CloseHandle(overlapped.hEvent);
            return false;
        }

        CloseHandle(overlapped.hEvent);
        return false;
    }

    CloseHandle(overlapped.hEvent);
    return bytes_written == length;
}

bool PipeServer::read_data(char* buffer, uint32_t length, DWORD timeout_ms) {
    if (m_pipe_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // On a byte-mode pipe a single ReadFile may return fewer bytes than
    // requested, so accumulate until the full length-prefixed frame has
    // been received rather than assuming one read yields the whole span.
    uint32_t total_read = 0;
    while (total_read < length) {
        OVERLAPPED overlapped = {};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) {
            return false;
        }

        DWORD bytes_read = 0;
        BOOL result = ReadFile(
            m_pipe_handle,
            buffer + total_read,
            length - total_read,
            &bytes_read,
            &overlapped
        );

        if (!result) {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                HANDLE wait_handles[2] = { overlapped.hEvent, m_stop_event };
                DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, timeout_ms);

                if (wait_result != WAIT_OBJECT_0) {
                    CancelIo(m_pipe_handle);
                    CloseHandle(overlapped.hEvent);
                    return false;
                }

                if (!GetOverlappedResult(m_pipe_handle, &overlapped, &bytes_read, FALSE)) {
                    CloseHandle(overlapped.hEvent);
                    return false;
                }
            } else {
                CloseHandle(overlapped.hEvent);
                return false;
            }
        }

        CloseHandle(overlapped.hEvent);

        if (bytes_read == 0) {
            return false;
        }

        total_read += bytes_read;
    }

    return true;
}

bool PipeServer::send_event(const std::string& event_type, const std::string& data) {
    std::ostringstream ss;
    ss << R"({"type":"event","event":")" << event_type
       << R"(","data":)" << data << '}';
    return broadcast_event(ss.str());
}

bool PipeServer::broadcast_event(const std::string& event_json) {
    if (!m_client_connected.load()) {
        return false;
    }

    return write_message(event_json.c_str(), static_cast<uint32_t>(event_json.size()));
}

namespace {

std::string escape_json_string(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (char ch : value) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[7];
                    std::snprintf(
                        buf,
                        sizeof(buf),
                        "\\u%04x",
                        static_cast<unsigned int>(static_cast<unsigned char>(ch))
                    );
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

}

std::string PipeServer::serialize_response(const PipeResponse& response) {
    std::ostringstream ss;
    ss << R"({"id":)" << response.id;
    if (response.success) {
        ss << R"(,"success":true,"result":)"
           << (response.result.empty() ? "null" : response.result);
    } else {
        ss << R"(,"success":false,"error":")" << escape_json_string(response.error) << '"';
    }
    ss << '}';
    return ss.str();
}

bool PipeServer::parse_message(const std::string& json, PipeMessage& msg) {
    msg.id = 0;
    msg.type.clear();
    msg.command.clear();
    msg.params.clear();

    auto find_string = [&json](const char* key) -> std::string {
        std::string search = "\"" + std::string(key) + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) {
            search = "\"" + std::string(key) + "\" :";
            pos = json.find(search);
        }
        if (pos == std::string::npos) return "";

        pos += search.length();
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

        if (pos >= json.length()) return "";

        if (json[pos] == '"') {
            size_t start = pos + 1;
            size_t end = json.find('"', start);
            while (end != std::string::npos && end > start) {
                size_t bs_count = 0;
                size_t check_pos = end;
                while (check_pos > start && json[check_pos - 1] == '\\') {
                    bs_count++;
                    check_pos--;
                }
                if (bs_count % 2 == 0) break;
                end = json.find('"', end + 1);
            }
            if (end != std::string::npos) {
                return json.substr(start, end - start);
            }
        }
        return "";
    };

    auto find_number = [&json](const char* key) -> uint32_t {
        std::string search = "\"" + std::string(key) + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) {
            search = "\"" + std::string(key) + "\" :";
            pos = json.find(search);
        }
        if (pos == std::string::npos) return 0;

        pos += search.length();
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

        if (pos >= json.length()) return 0;

        size_t end = pos;
        while (end < json.length() && json[end] >= '0' && json[end] <= '9') end++;

        if (end > pos) {
            return static_cast<uint32_t>(std::stoul(json.substr(pos, end - pos)));
        }
        return 0;
    };

    auto find_object = [&json](const char* key) -> std::string {
        std::string search = "\"" + std::string(key) + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) {
            search = "\"" + std::string(key) + "\" :";
            pos = json.find(search);
        }
        if (pos == std::string::npos) return "{}";

        pos += search.length();
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

        if (pos >= json.length() || json[pos] != '{') return "{}";

        int depth = 1;
        size_t start = pos;
        pos++;

        while (pos < json.length() && depth > 0) {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') depth--;
            else if (json[pos] == '"') {
                pos++;
                while (pos < json.length() && !(json[pos] == '"' && json[pos-1] != '\\')) pos++;
            }
            pos++;
        }

        return json.substr(start, pos - start);
    };

    msg.id = find_number("id");
    msg.type = find_string("type");
    msg.command = find_string("command");
    msg.params = find_object("params");

    return !msg.command.empty();
}

}
