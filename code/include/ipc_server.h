#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

class VpnDaemon;

class IpcServer {
public:
    using StopCallback = std::function<void()>;

    IpcServer();
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    bool start(const std::string& socket_path, VpnDaemon* daemon);
    void stop();

    void set_stop_callback(StopCallback cb) { stop_callback_ = std::move(cb); }

private:
    void accept_loop();
    void handle_client(int client_fd);
    std::string handle_command(const std::string& cmd);

    int server_fd_;
    std::string socket_path_;
    std::atomic<bool> running_;
    std::thread thread_;
    VpnDaemon* daemon_;
    StopCallback stop_callback_;
};
