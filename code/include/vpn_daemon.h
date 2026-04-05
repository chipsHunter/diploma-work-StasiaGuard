#pragma once

#include "config.h"
#include "ipc_server.h"
#include "key_store.h"
#include "peer_registry.h"
#include "routing_table.h"
#include "session_manager.h"
#include "tls_profile.h"
#include "tun_device.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <thread>

class NoiseHandshake;

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

    bool setup_tun(const Config& config);
    bool setup_udp(const Config& config);
    bool perform_handshake(const Config& config);
    bool handle_handshake(const uint8_t* buf, ssize_t n,
                          struct sockaddr_in& from, socklen_t from_len);
    void initiate_rekey(const std::string& peer_id);

    void tun_to_udp();
    void udp_to_tun();

    TunDevice tun_;
    int udp_fd_;

    KeyStore key_store_;
    PeerRegistry peer_registry_;
    RoutingTable routing_table_;
    SessionManager session_mgr_;

    // Client-only: server endpoint
    struct sockaddr_in server_addr_{};
    socklen_t server_addr_len_ = sizeof(struct sockaddr_in);

    // Client-only: pending rekey handshake
    std::unique_ptr<NoiseHandshake> pending_rekey_;
    std::string rekey_peer_id_;
    std::mutex rekey_mutex_;

    std::atomic<bool> running_;
    std::thread tun_thread_;
    std::thread udp_thread_;

    Config::Role role_;
    bool use_tls_;
    IpcServer ipc_;

    std::shared_ptr<TrafficProfile> make_profile();
};
