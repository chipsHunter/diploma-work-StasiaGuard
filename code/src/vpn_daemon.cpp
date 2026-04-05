#include "vpn_daemon.h"
#include "crypto_engine.h"
#include "noise_handshake.h"
#include "packet.h"

#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

VpnDaemon::VpnDaemon()
    : udp_fd_(-1)
    , running_(false)
    , role_(Config::Role::CLIENT) {
}

VpnDaemon::~VpnDaemon() {
    stop();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool VpnDaemon::start(const Config& config) {
    role_ = config.role();
    peer_configs_ = config.peers();

    if (!CryptoEngine::init()) {
        std::cerr << "error: failed to init libsodium" << std::endl;
        return false;
    }

    if (!load_keys(config))  return false;
    if (!setup_tun(config))  return false;
    if (!setup_udp(config))  return false;

    // Client performs handshake before starting threads.
    // Server starts threads immediately — handshakes arrive via UDP.
    if (role_ == Config::Role::CLIENT) {
        if (!perform_handshake(config)) return false;
    }

    running_ = true;
    tun_thread_ = std::thread(&VpnDaemon::tun_to_udp, this);
    udp_thread_ = std::thread(&VpnDaemon::udp_to_tun, this);

    if (role_ == Config::Role::SERVER)
        std::cout << "server ready, waiting for clients" << std::endl;
    else
        std::cout << "tunnel established, forwarding traffic" << std::endl;
    return true;
}

void VpnDaemon::wait() {
    if (tun_thread_.joinable()) tun_thread_.join();
    if (udp_thread_.joinable()) udp_thread_.join();
}

void VpnDaemon::stop() {
    if (!running_.exchange(false)) return;

    std::cout << "shutting down..." << std::endl;
    tun_.close();
    if (udp_fd_ >= 0) {
        ::close(udp_fd_);
        udp_fd_ = -1;
    }
}

// ---------------------------------------------------------------------------
// Peer lookup helpers
// ---------------------------------------------------------------------------

std::shared_ptr<PeerState> VpnDaemon::find_peer_by_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(ip);
    return (it != peers_.end()) ? it->second : nullptr;
}

std::shared_ptr<PeerState> VpnDaemon::find_peer_by_addr(const struct sockaddr_in& addr) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& [ip, peer] : peers_) {
        if (peer->addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
            peer->addr.sin_port == addr.sin_port)
            return peer;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

bool VpnDaemon::load_keys(const Config& config) {
    std::ifstream f(config.private_key_path());
    if (!f) {
        std::cerr << "error: cannot open private key: "
                  << config.private_key_path() << std::endl;
        return false;
    }

    std::string b64;
    std::getline(f, b64);
    uint8_t priv[32];
    if (!Config::base64_decode(b64, priv, 32)) {
        std::cerr << "error: invalid private key format" << std::endl;
        return false;
    }

    local_static_ = KeyPair::from_private_key(priv);
    sodium_memzero(priv, 32);

    if (config.peers().empty()) {
        std::cerr << "error: no peers configured" << std::endl;
        return false;
    }

    std::cout << "local public key: "
              << Config::base64_encode(local_static_.public_key(), 32) << std::endl;
    return true;
}

bool VpnDaemon::setup_tun(const Config& config) {
    if (!tun_.open("tun0")) return false;
    tun_.configure(config.tun_ip(), config.tun_mask());
    std::cout << "tun0: " << config.tun_ip() << "/"
              << config.tun_mask() << std::endl;
    return true;
}

bool VpnDaemon::setup_udp(const Config& config) {
    udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd_ < 0) {
        std::cerr << "error: cannot create UDP socket" << std::endl;
        return false;
    }

    if (role_ == Config::Role::SERVER) {
        struct sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(config.listen_port());
        bind_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(udp_fd_, reinterpret_cast<struct sockaddr*>(&bind_addr),
                 sizeof(bind_addr)) < 0) {
            std::cerr << "error: cannot bind to port "
                      << config.listen_port() << std::endl;
            return false;
        }
        std::cout << "listening on UDP :" << config.listen_port() << std::endl;
    }

    if (role_ == Config::Role::CLIENT) {
        const std::string& ep = config.peers()[0].endpoint;
        auto colon = ep.rfind(':');
        if (colon == std::string::npos) {
            std::cerr << "error: invalid endpoint format (expected ip:port)" << std::endl;
            return false;
        }
        std::string host = ep.substr(0, colon);
        uint16_t port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));

        server_addr_.sin_family = AF_INET;
        server_addr_.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &server_addr_.sin_addr) != 1) {
            std::cerr << "error: invalid server address: " << host << std::endl;
            return false;
        }
        server_addr_len_ = sizeof(server_addr_);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

bool VpnDaemon::perform_handshake(const Config& config) {
    // Client-only: initiate handshake with server
    NoiseHandshake hs(NoiseHandshake::Role::INITIATOR,
                      local_static_.private_key(),
                      local_static_.public_key(),
                      config.peers()[0].public_key);

    uint8_t buf[256];
    buf[0] = MSG_HANDSHAKE1;
    size_t msg_len;
    if (!hs.write_message1(buf + 1, &msg_len)) {
        std::cerr << "error: failed to create handshake msg1" << std::endl;
        return false;
    }

    sendto(udp_fd_, buf, 1 + msg_len, 0,
           reinterpret_cast<struct sockaddr*>(&server_addr_), server_addr_len_);
    std::cout << "handshake msg1 sent" << std::endl;

    struct timeval tv{5, 0};
    setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int attempt = 0; attempt < 3; attempt++) {
        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(udp_fd_, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr*>(&from), &from_len);
        if (n > 0 && buf[0] == MSG_HANDSHAKE2) {
            if (!hs.read_message2(buf + 1, n - 1)) {
                std::cerr << "error: invalid handshake msg2" << std::endl;
                return false;
            }
            std::cout << "handshake msg2 received" << std::endl;

            uint8_t sk[32], rk[32];
            hs.split(sk, rk);

            auto peer = std::make_shared<PeerState>();
            peer->session = std::make_shared<Session>(sk, rk);
            peer->addr = server_addr_;
            peer->addr_len = server_addr_len_;
            std::memcpy(peer->public_key, config.peers()[0].public_key, 32);
            peer->allowed_ip = config.peers()[0].allowed_ip;

            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peers_[peer->allowed_ip] = peer;
            }

            sodium_memzero(sk, 32);
            sodium_memzero(rk, 32);

            tv = {0, 0};
            setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            return true;
        }

        if (attempt < 2) {
            std::cout << "retrying handshake..." << std::endl;
            sendto(udp_fd_, buf, 1 + msg_len, 0,
                   reinterpret_cast<struct sockaddr*>(&server_addr_),
                   server_addr_len_);
        }
    }

    std::cerr << "error: handshake timed out" << std::endl;
    return false;
}

bool VpnDaemon::handle_handshake(const uint8_t* buf, ssize_t n,
                                 struct sockaddr_in& from, socklen_t from_len) {
    NoiseHandshake hs(NoiseHandshake::Role::RESPONDER,
                      local_static_.private_key(),
                      local_static_.public_key(),
                      nullptr);

    if (!hs.read_message1(buf + 1, n - 1)) {
        std::cerr << "error: invalid handshake msg1" << std::endl;
        return false;
    }

    // Find matching peer config by public key
    const PeerInfo* matched = nullptr;
    for (const auto& pc : peer_configs_) {
        if (std::memcmp(pc.public_key, hs.remote_static_public_key(), 32) == 0) {
            matched = &pc;
            break;
        }
    }
    if (!matched) {
        std::cerr << "error: unknown peer" << std::endl;
        return false;
    }

    uint8_t out[256];
    out[0] = MSG_HANDSHAKE2;
    size_t msg_len;
    if (!hs.write_message2(out + 1, &msg_len)) return false;

    sendto(udp_fd_, out, 1 + msg_len, 0,
           reinterpret_cast<struct sockaddr*>(&from), from_len);

    uint8_t sk[32], rk[32];
    hs.split(sk, rk);

    auto peer = std::make_shared<PeerState>();
    peer->session = std::make_shared<Session>(sk, rk);
    peer->addr = from;
    peer->addr_len = from_len;
    std::memcpy(peer->public_key, hs.remote_static_public_key(), 32);
    peer->allowed_ip = matched->allowed_ip;

    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peers_[matched->allowed_ip] = peer;
    }

    sodium_memzero(sk, 32);
    sodium_memzero(rk, 32);

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
    std::cout << "peer " << matched->allowed_ip << " connected from "
              << addr_str << ":" << ntohs(from.sin_port) << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Data forwarding threads
// ---------------------------------------------------------------------------

void VpnDaemon::tun_to_udp() {
    uint8_t buf[Packet::MAX_SIZE + Session::OVERHEAD + 1];
    struct pollfd pfd;
    pfd.fd = tun_.fd();
    pfd.events = POLLIN;

    while (running_) {
        int ret = poll(&pfd, 1, 500);
        if (ret <= 0) continue;

        Packet pkt;
        if (!tun_.read_packet(pkt)) break;

        std::shared_ptr<PeerState> peer;

        if (role_ == Config::Role::CLIENT) {
            // Client: all traffic goes to the single peer (server)
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (!peers_.empty())
                peer = peers_.begin()->second;
        } else {
            // Server: route by destination IP
            struct in_addr dst;
            dst.s_addr = pkt.get_dest_ip();
            char dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));
            peer = find_peer_by_ip(dst_str);
        }

        if (!peer || !peer->session) continue;

        buf[0] = MSG_DATA;
        size_t enc_len;
        if (!peer->session->encrypt(buf + 1, &enc_len, pkt.data(), pkt.length()))
            continue;

        sendto(udp_fd_, buf, 1 + enc_len, 0,
               reinterpret_cast<struct sockaddr*>(&peer->addr), peer->addr_len);
    }
}

void VpnDaemon::udp_to_tun() {
    uint8_t buf[2048];
    struct pollfd pfd;
    pfd.fd = udp_fd_;
    pfd.events = POLLIN;

    while (running_) {
        int ret = poll(&pfd, 1, 500);
        if (ret <= 0) continue;

        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(udp_fd_, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr*>(&from), &from_len);
        if (n <= 0) break;
        if (n < 2) continue;

        if (buf[0] == MSG_HANDSHAKE1 && role_ == Config::Role::SERVER) {
            handle_handshake(buf, n, from, from_len);
            continue;
        }

        if (buf[0] != MSG_DATA) continue;

        // Find session: by source address (server) or use single peer (client)
        std::shared_ptr<PeerState> peer;

        if (role_ == Config::Role::CLIENT) {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (!peers_.empty())
                peer = peers_.begin()->second;
        } else {
            peer = find_peer_by_addr(from);
        }

        if (!peer || !peer->session) continue;

        uint8_t plaintext[2048];
        size_t pt_len;
        if (!peer->session->decrypt(plaintext, &pt_len, buf + 1, n - 1))
            continue;

        Packet pkt;
        std::memcpy(pkt.data(), plaintext, pt_len);
        pkt.set_length(pt_len);
        tun_.write_packet(pkt);
    }
}
