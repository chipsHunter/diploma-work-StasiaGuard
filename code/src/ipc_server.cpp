#include "ipc_server.h"
#include "metrics.h"
#include "session_manager.h"
#include "vpn_daemon.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

IpcServer::IpcServer()
    : server_fd_(-1)
    , running_(false)
    , daemon_(nullptr) {
}

IpcServer::~IpcServer() {
    stop();
}

bool IpcServer::start(const std::string& socket_path, VpnDaemon* daemon) {
    daemon_ = daemon;
    socket_path_ = socket_path;

    ::unlink(socket_path_.c_str());

    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "error: cannot create IPC socket" << std::endl;
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) < 0) {
        std::cerr << "error: cannot bind IPC socket to " << socket_path_ << std::endl;
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    if (listen(server_fd_, 5) < 0) {
        std::cerr << "error: cannot listen on IPC socket" << std::endl;
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    running_ = true;
    thread_ = std::thread(&IpcServer::accept_loop, this);
    return true;
}

void IpcServer::stop() {
    if (!running_.exchange(false)) return;

    if (server_fd_ >= 0) {
        ::shutdown(server_fd_, SHUT_RDWR);
        ::close(server_fd_);
        server_fd_ = -1;
    }

    if (thread_.joinable())
        thread_.join();

    ::unlink(socket_path_.c_str());
}

void IpcServer::accept_loop() {
    while (running_) {
        struct timeval tv{1, 0};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd_, &fds);

        int ret = select(server_fd_ + 1, &fds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        int client_fd = accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) continue;

        handle_client(client_fd);
        ::close(client_fd);
    }
}

void IpcServer::handle_client(int client_fd) {
    char buf[4096];
    ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    buf[n] = '\0';

    // Strip whitespace/newlines
    std::string cmd(buf);
    while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
        cmd.pop_back();

    std::string response = handle_command(cmd);
    response += "\n";
    send(client_fd, response.c_str(), response.size(), 0);
}

std::string IpcServer::handle_command(const std::string& cmd) {
    // Simple command parsing: {"command":"..."} or plain text
    std::string command;

    auto pos = cmd.find("\"command\"");
    if (pos != std::string::npos) {
        auto colon = cmd.find(':', pos);
        auto quote1 = cmd.find('"', colon + 1);
        auto quote2 = cmd.find('"', quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos)
            command = cmd.substr(quote1 + 1, quote2 - quote1 - 1);
    } else {
        command = cmd;
    }

    if (command == "metrics") {
        return global_metrics().to_json();
    }

    if (command == "status") {
        auto& m = global_metrics();
        std::ostringstream ss;
        ss << "{\"status\":\"running\""
           << ",\"uptime_seconds\":" << m.uptime_seconds()
           << ",\"active_peers\":" << m.active_peers.load()
           << ",\"bytes_sent\":" << m.bytes_sent.load()
           << ",\"bytes_received\":" << m.bytes_received.load()
           << "}";
        return ss.str();
    }

    if (command == "stop") {
        if (stop_callback_) stop_callback_();
        return "{\"status\":\"stopping\"}";
    }

    return "{\"error\":\"unknown command\"}";
}
