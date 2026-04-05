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
    , peer_addr_len_(sizeof(peer_addr_))
    , running_(false)
    , role_(Config::Role::CLIENT) {
    std::memset(&peer_addr_, 0, sizeof(peer_addr_));
    std::memset(peer_public_key_, 0, 32);
}

VpnDaemon::~VpnDaemon() {
    stop();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool VpnDaemon::start(const Config& config) {
    role_ = config.role();

    if (!CryptoEngine::init()) {
        std::cerr << "error: failed to init libsodium\n";
        return false;
    }

    if (!load_keys(config))  return false;
    if (!setup_tun(config))  return false;
    if (!setup_udp(config))  return false;
    if (!perform_handshake(config)) return false;

    running_ = true;
    tun_thread_ = std::thread(&VpnDaemon::tun_to_udp, this);
    udp_thread_ = std::thread(&VpnDaemon::udp_to_tun, this);

    std::cout << "tunnel established, forwarding traffic" << std::endl;
    return true;
}

std::shared_ptr<Session> VpnDaemon::get_session() {
    std::lock_guard<std::mutex> lock(session_mutex_);
    return session_;
}

void VpnDaemon::set_session(std::shared_ptr<Session> s) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    session_ = std::move(s);
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
// Setup
// ---------------------------------------------------------------------------

bool VpnDaemon::load_keys(const Config& config) {
    std::ifstream f(config.private_key_path());
    if (!f) {
        std::cerr << "error: cannot open private key: "
                  << config.private_key_path() << "\n";
        return false;
    }

    std::string b64;
    std::getline(f, b64);
    uint8_t priv[32];
    if (!Config::base64_decode(b64, priv, 32)) {
        std::cerr << "error: invalid private key format\n";
        return false;
    }

    local_static_ = KeyPair::from_private_key(priv);
    sodium_memzero(priv, 32);

    if (config.peers().empty()) {
        std::cerr << "error: no peers configured\n";
        return false;
    }
    std::memcpy(peer_public_key_, config.peers()[0].public_key, 32);

    std::cout << "local public key: "
              << Config::base64_encode(local_static_.public_key(), 32) << "\n";
    return true;
}

bool VpnDaemon::setup_tun(const Config& config) {
    if (!tun_.open("tun0")) return false;
    tun_.configure(config.tun_ip(), config.tun_mask());
    std::cout << "tun0: " << config.tun_ip() << "/"
              << config.tun_mask() << "\n";
    return true;
}

bool VpnDaemon::setup_udp(const Config& config) {
    udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd_ < 0) {
        std::cerr << "error: cannot create UDP socket\n";
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
                      << config.listen_port() << "\n";
            return false;
        }
        std::cout << "listening on UDP :" << config.listen_port() << "" << std::endl;
    }

    // For client, resolve server endpoint
    if (role_ == Config::Role::CLIENT && !config.peers().empty()) {
        const std::string& ep = config.peers()[0].endpoint;
        auto colon = ep.rfind(':');
        if (colon == std::string::npos) {
            std::cerr << "error: invalid endpoint format (expected ip:port)\n";
            return false;
        }
        std::string host = ep.substr(0, colon);
        uint16_t port = static_cast<uint16_t>(std::stoi(ep.substr(colon + 1)));

        peer_addr_.sin_family = AF_INET;
        peer_addr_.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &peer_addr_.sin_addr) != 1) {
            std::cerr << "error: invalid server address: " << host << "\n";
            return false;
        }
        peer_addr_len_ = sizeof(peer_addr_);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

bool VpnDaemon::perform_handshake(const Config& config) {
    if (role_ == Config::Role::CLIENT) {
        // Client: initiator — knows server's static key
        NoiseHandshake hs(NoiseHandshake::Role::INITIATOR,
                          local_static_.private_key(),
                          local_static_.public_key(),
                          peer_public_key_);

        // Write and send msg1
        uint8_t buf[256];
        buf[0] = MSG_HANDSHAKE1;
        size_t msg_len;
        if (!hs.write_message1(buf + 1, &msg_len)) {
            std::cerr << "error: failed to create handshake msg1\n";
            return false;
        }

        sendto(udp_fd_, buf, 1 + msg_len, 0,
               reinterpret_cast<struct sockaddr*>(&peer_addr_), peer_addr_len_);
        std::cout << "handshake msg1 sent" << std::endl;

        // Wait for msg2 with timeout + retry
        struct timeval tv{5, 0};
        setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        for (int attempt = 0; attempt < 3; attempt++) {
            ssize_t n = recvfrom(udp_fd_, buf, sizeof(buf), 0,
                                 reinterpret_cast<struct sockaddr*>(&peer_addr_),
                                 &peer_addr_len_);
            if (n > 0 && buf[0] == MSG_HANDSHAKE2) {
                if (!hs.read_message2(buf + 1, n - 1)) {
                    std::cerr << "error: invalid handshake msg2\n";
                    return false;
                }
                std::cout << "handshake msg2 received" << std::endl;

                uint8_t sk[32], rk[32];
                hs.split(sk, rk);
                set_session(std::make_shared<Session>(sk, rk));
                sodium_memzero(sk, 32);
                sodium_memzero(rk, 32);

                // Clear timeout
                tv = {0, 0};
                setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                return true;
            }

            if (attempt < 2) {
                std::cout << "retrying handshake..." << std::endl;
                sendto(udp_fd_, buf, 1 + msg_len, 0,
                       reinterpret_cast<struct sockaddr*>(&peer_addr_),
                       peer_addr_len_);
            }
        }

        std::cerr << "error: handshake timed out\n";
        return false;

    } else {
        // Server: responder — wait for client's msg1
        std::cout << "waiting for handshake..." << std::endl;

        uint8_t buf[256];
        ssize_t n = recvfrom(udp_fd_, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr*>(&peer_addr_),
                             &peer_addr_len_);
        if (n <= 0 || buf[0] != MSG_HANDSHAKE1) {
            std::cerr << "error: expected handshake msg1\n";
            return false;
        }

        NoiseHandshake hs(NoiseHandshake::Role::RESPONDER,
                          local_static_.private_key(),
                          local_static_.public_key(),
                          nullptr);

        if (!hs.read_message1(buf + 1, n - 1)) {
            std::cerr << "error: invalid handshake msg1\n";
            return false;
        }

        // Verify peer is authorized
        bool authorized = false;
        for (const auto& peer : config.peers()) {
            if (std::memcmp(peer.public_key,
                            hs.remote_static_public_key(), 32) == 0) {
                authorized = true;
                break;
            }
        }
        if (!authorized) {
            std::cerr << "error: unknown peer\n";
            return false;
        }

        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr_.sin_addr, addr_str, sizeof(addr_str));
        std::cout << "handshake msg1 from " << addr_str
                  << ":" << ntohs(peer_addr_.sin_port) << "\n";

        // Write and send msg2
        buf[0] = MSG_HANDSHAKE2;
        size_t msg_len;
        if (!hs.write_message2(buf + 1, &msg_len)) {
            std::cerr << "error: failed to create handshake msg2\n";
            return false;
        }

        sendto(udp_fd_, buf, 1 + msg_len, 0,
               reinterpret_cast<struct sockaddr*>(&peer_addr_), peer_addr_len_);
        std::cout << "handshake msg2 sent" << std::endl;

        uint8_t sk[32], rk[32];
        hs.split(sk, rk);
        set_session(std::make_shared<Session>(sk, rk));
        sodium_memzero(sk, 32);
        sodium_memzero(rk, 32);

        return true;
    }
}

bool VpnDaemon::handle_rehandshake(const uint8_t* buf, ssize_t n,
                                   struct sockaddr_in& from, socklen_t from_len) {
    NoiseHandshake hs(NoiseHandshake::Role::RESPONDER,
                      local_static_.private_key(),
                      local_static_.public_key(),
                      nullptr);

    if (!hs.read_message1(buf + 1, n - 1)) {
        std::cerr << "error: invalid re-handshake msg1" << std::endl;
        return false;
    }

    if (std::memcmp(hs.remote_static_public_key(), peer_public_key_, 32) != 0) {
        std::cerr << "error: re-handshake from unknown peer" << std::endl;
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
    set_session(std::make_shared<Session>(sk, rk));
    sodium_memzero(sk, 32);
    sodium_memzero(rk, 32);

    {
        std::lock_guard<std::mutex> lock(addr_mutex_);
        peer_addr_ = from;
        peer_addr_len_ = from_len;
    }

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
    std::cout << "re-handshake from " << addr_str
              << ":" << ntohs(from.sin_port) << std::endl;
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

        auto sess = get_session();
        if (!sess) continue;

        buf[0] = MSG_DATA;
        size_t enc_len;
        if (!sess->encrypt(buf + 1, &enc_len, pkt.data(), pkt.length()))
            continue;

        struct sockaddr_in addr;
        socklen_t addr_len;
        {
            std::lock_guard<std::mutex> lock(addr_mutex_);
            addr = peer_addr_;
            addr_len = peer_addr_len_;
        }
        sendto(udp_fd_, buf, 1 + enc_len, 0,
               reinterpret_cast<struct sockaddr*>(&addr), addr_len);
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
            handle_rehandshake(buf, n, from, from_len);
            continue;
        }

        if (buf[0] != MSG_DATA) continue;

        auto sess = get_session();
        if (!sess) continue;

        uint8_t plaintext[2048];
        size_t pt_len;
        if (!sess->decrypt(plaintext, &pt_len, buf + 1, n - 1))
            continue;

        Packet pkt;
        std::memcpy(pkt.data(), plaintext, pt_len);
        pkt.set_length(pt_len);
        tun_.write_packet(pkt);
    }
}
