/**
 * @file pipe_server.cpp
 * @brief Named pipe server implementation for Intellicrack IPC
 */

#include "pipe_server.h"
#include <sddl.h>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <vector>

namespace intellicrack {

namespace {

/**
 * @brief Build a security descriptor granting pipe access to the current user
 *        and Local System only.
 *
 * The pipe drives full write access to the debuggee, so its DACL must not be
 * the permissive default that CreateNamedPipe applies when no
 * SECURITY_ATTRIBUTES is supplied. This queries the current process token for
 * the owning user's SID and constructs an SDDL descriptor granting GENERIC_ALL
 * to that SID and to Local System (SY), with a protected DACL so no inherited
 * ACE can widen it.
 *
 * @param out_sd Receives a LocalAlloc'd security descriptor on success; the
 *               caller must LocalFree it once the pipe has been created.
 * @return true and a valid descriptor on success; false (with @p out_sd left
 *         null) when the token or SID could not be resolved, in which case the
 *         caller should still apply the first-instance/reject-remote flags.
 */
bool build_pipe_security_descriptor(PSECURITY_DESCRIPTOR& out_sd) {
    out_sd = nullptr;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(token);
        return false;
    }

    std::vector<char> buffer(needed);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);

    auto* token_user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPSTR sid_str = nullptr;
    if (!ConvertSidToStringSidA(token_user->User.Sid, &sid_str)) {
        return false;
    }

    // D:P               protected DACL (no inheritance widens it)
    // (A;;GA;;;<user>)  GENERIC_ALL for the owning user
    // (A;;GA;;;SY)      GENERIC_ALL for Local System
    std::string sddl = "D:P(A;;GA;;;";
    sddl += sid_str;
    sddl += ")(A;;GA;;;SY)";
    LocalFree(sid_str);

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }

    out_sd = sd;
    return true;
}

}  // namespace

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

    // Restrict the endpoint before it exists. The name is a fixed, well-known
    // constant that any local process could otherwise pre-create (squatting on
    // the target-control channel) or connect to (driving writes into the
    // debuggee). FILE_FLAG_FIRST_PIPE_INSTANCE makes creation fail if the name
    // is already taken, PIPE_REJECT_REMOTE_CLIENTS refuses over-the-network
    // clients, and the DACL confines connections to the current user and Local
    // System.
    PSECURITY_DESCRIPTOR security_descriptor = nullptr;
    SECURITY_ATTRIBUTES security_attributes = {};
    LPSECURITY_ATTRIBUTES security_attributes_ptr = nullptr;
    if (build_pipe_security_descriptor(security_descriptor)) {
        security_attributes.nLength = sizeof(security_attributes);
        security_attributes.lpSecurityDescriptor = security_descriptor;
        security_attributes.bInheritHandle = FALSE;
        security_attributes_ptr = &security_attributes;
    }

    m_pipe_handle =
        CreateNamedPipeA(PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                         PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, security_attributes_ptr);

    if (security_descriptor) {
        LocalFree(security_descriptor);
    }

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

            if (wait_result != WAIT_OBJECT_0) {
                // Stop signalled (or the wait failed) while the connect was
                // still pending: cancel and drain it before the stack
                // OVERLAPPED/event are destroyed, so a late connect completion
                // cannot reference freed memory.
                CancelIo(m_pipe_handle);
                DWORD drained = 0;
                GetOverlappedResult(m_pipe_handle, &overlapped, &drained, TRUE);
                CloseHandle(overlapped.hEvent);
                return false;
            }

            CloseHandle(overlapped.hEvent);
            return true;
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

            // Timeout or stop: cancel and drain the pending write before the
            // stack OVERLAPPED/event are destroyed, so the kernel is finished
            // with them before they leave scope (see read_data).
            CancelIo(m_pipe_handle);
            GetOverlappedResult(m_pipe_handle, &overlapped, &bytes_written, TRUE);
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
                    // Cancel the pending read and drain its completion before
                    // the stack OVERLAPPED and its event go out of scope. A
                    // bare CancelIo only *requests* cancellation; the kernel
                    // may still be writing into buffer/overlapped when this
                    // frame returns. GetOverlappedResult(..., TRUE) blocks
                    // until the I/O has truly finished (with or without the
                    // cancel), so a late completion cannot touch freed memory.
                    CancelIo(m_pipe_handle);
                    DWORD drained = 0;
                    GetOverlappedResult(m_pipe_handle, &overlapped, &drained, TRUE);
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

        // Accumulate manually and saturate at UINT32_MAX rather than calling
        // std::stoul, which throws std::out_of_range on an over-long run of
        // digits (e.g. a 20-digit "id"). This runs on the "id" of *every*
        // inbound frame, before any handler and outside the dispatch
        // exception firewall, so a throw here would unwind straight out of
        // the server thread proc and terminate the x64dbg process.
        uint64_t value = 0;
        for (size_t i = pos; i < end; i++) {
            value = (value * 10) + static_cast<uint64_t>(json[i] - '0');
            if (value > 0xFFFFFFFFULL) {
                value = 0xFFFFFFFFULL;
                break;
            }
        }
        return static_cast<uint32_t>(value);
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
