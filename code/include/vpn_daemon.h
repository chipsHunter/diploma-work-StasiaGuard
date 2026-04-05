#pragma once

#include "config.h"
#include "key_pair.h"
#include "session.h"
#include "tun_device.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <thread>

struct PeerState {
    std::shared_ptr<Session> session;
    struct sockaddr_in addr{};
    socklen_t addr_len = sizeof(struct sockaddr_in);
    uint8_t public_key[32]{};
    std::string allowed_ip;
};

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
    bool handle_handshake(const uint8_t* buf, ssize_t n,
                          struct sockaddr_in& from, socklen_t from_len);

    std::shared_ptr<PeerState> find_peer_by_ip(const std::string& ip);
    std::shared_ptr<PeerState> find_peer_by_addr(const struct sockaddr_in& addr);

    void tun_to_udp();
    void udp_to_tun();

    TunDevice tun_;
    int udp_fd_;
    KeyPair local_static_;

    // Peer sessions indexed by allowed_ip
    std::map<std::string, std::shared_ptr<PeerState>> peers_;
    std::mutex peers_mutex_;

    // Peer configs from YAML (for authenticating handshakes)
    std::vector<PeerInfo> peer_configs_;

    // Client-only: server endpoint for initial handshake
    struct sockaddr_in server_addr_{};
    socklen_t server_addr_len_ = sizeof(struct sockaddr_in);

    std::atomic<bool> running_;
    std::thread tun_thread_;
    std::thread udp_thread_;

    Config::Role role_;
};
