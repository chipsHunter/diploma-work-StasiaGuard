#pragma once

#include "config.h"
#include "key_pair.h"
#include "session.h"
#include "tun_device.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <thread>

class VpnDaemon {
public:
    VpnDaemon();
    ~VpnDaemon();

    VpnDaemon(const VpnDaemon&) = delete;
    VpnDaemon& operator=(const VpnDaemon&) = delete;

    bool start(const Config& config);
    void wait();
    void stop();

private:
    enum MsgType : uint8_t {
        MSG_HANDSHAKE1 = 1,
        MSG_HANDSHAKE2 = 2,
        MSG_DATA       = 3
    };

    bool load_keys(const Config& config);
    bool setup_tun(const Config& config);
    bool setup_udp(const Config& config);
    bool perform_handshake(const Config& config);
    bool handle_rehandshake(const uint8_t* buf, ssize_t n,
                            struct sockaddr_in& from, socklen_t from_len);

    std::shared_ptr<Session> get_session();
    void set_session(std::shared_ptr<Session> s);

    void tun_to_udp();
    void udp_to_tun();

    TunDevice tun_;
    int udp_fd_;
    std::shared_ptr<Session> session_;
    std::mutex session_mutex_;
    KeyPair local_static_;

    struct sockaddr_in peer_addr_;
    socklen_t peer_addr_len_;
    std::mutex addr_mutex_;

    std::atomic<bool> running_;
    std::thread tun_thread_;
    std::thread udp_thread_;

    Config::Role role_;
    uint8_t peer_public_key_[32];
};
