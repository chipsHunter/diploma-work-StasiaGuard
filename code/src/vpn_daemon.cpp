#include "vpn_daemon.h"
#include "crypto_engine.h"
#include "noise_handshake.h"
#include "packet.h"
#include "tls_record_builder.h"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

VpnDaemon::VpnDaemon()
    : udp_fd_(-1)
    , running_(false)
    , role_(Config::Role::CLIENT)
    , use_tls_(false) {
}

std::shared_ptr<TrafficProfile> VpnDaemon::make_profile() {
    if (use_tls_)
        return std::make_shared<TlsProfile>();
    return nullptr;
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
        std::cerr << "error: failed to init libsodium" << std::endl;
        return false;
    }

    if (!key_store_.load_private_key(config.private_key_path()))
        return false;

    std::cout << "local public key: "
              << Config::base64_encode(key_store_.public_key(), 32) << std::endl;

    peer_registry_.load(config.peers());
    use_tls_ = (config.traffic_profile() == "tls");
    if (use_tls_)
        std::cout << "traffic profile: TLS 1.3 mimicry" << std::endl;

    if (!setup_tun(config)) return false;
    if (!setup_udp(config)) return false;

    if (role_ == Config::Role::CLIENT) {
        if (!perform_handshake(config)) return false;
    }

    // Set up rekey callback (client initiates, server just accepts)
    session_mgr_.set_rekey_callback([this](const std::string& peer_id) {
        if (role_ == Config::Role::CLIENT)
            initiate_rekey(peer_id);
        else
            std::cout << "rekey pending for peer " << peer_id
                      << " (waiting for client)" << std::endl;
    });

    running_ = true;
    session_mgr_.start_rekey_timer();
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
    session_mgr_.stop_rekey_timer();
    tun_.close();
    if (udp_fd_ >= 0) {
        ::close(udp_fd_);
        udp_fd_ = -1;
    }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

bool VpnDaemon::setup_tun(const Config& config) {
    if (!tun_.open("tun0")) return false;
    tun_.configure(config.tun_ip(), config.tun_mask());
    std::cout << "tun0: " << config.tun_ip() << "/"
              << config.tun_mask() << std::endl;

    if (role_ == Config::Role::SERVER)
        system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1");

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
            std::cerr << "error: invalid endpoint (expected ip:port)" << std::endl;
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
    const auto& peer = config.peers()[0];
    auto profile = make_profile();

    NoiseHandshake hs(NoiseHandshake::Role::INITIATOR,
                      key_store_.private_key(),
                      key_store_.public_key(),
                      peer.public_key);

    uint8_t noise_buf[256], send_buf[2048];
    size_t noise_len;
    if (!hs.write_message1(noise_buf, &noise_len)) {
        std::cerr << "error: failed to create handshake msg1" << std::endl;
        return false;
    }

    size_t send_len;
    if (profile) {
        send_len = profile->wrap_handshake(send_buf, noise_buf, noise_len, true);
    } else {
        send_buf[0] = MSG_HANDSHAKE1;
        std::memcpy(send_buf + 1, noise_buf, noise_len);
        send_len = 1 + noise_len;
    }

    sendto(udp_fd_, send_buf, send_len, 0,
           reinterpret_cast<struct sockaddr*>(&server_addr_), server_addr_len_);
    std::cout << "handshake msg1 sent" << std::endl;

    struct timeval tv{5, 0};
    setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t recv_buf[2048];
    for (int attempt = 0; attempt < 3; attempt++) {
        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(udp_fd_, recv_buf, sizeof(recv_buf), 0,
                             reinterpret_cast<struct sockaddr*>(&from), &from_len);
        if (n <= 0) goto retry;

        {
            uint8_t noise_msg2[128];
            size_t noise_msg2_len;
            bool ok = false;

            if (profile) {
                ok = profile->unwrap_handshake(noise_msg2, &noise_msg2_len,
                                               recv_buf, n, true);
            } else if (recv_buf[0] == MSG_HANDSHAKE2) {
                std::memcpy(noise_msg2, recv_buf + 1, n - 1);
                noise_msg2_len = n - 1;
                ok = true;
            }

            if (ok && hs.read_message2(noise_msg2, noise_msg2_len)) {
                std::cout << "handshake msg2 received" << std::endl;

                uint8_t sk[32], rk[32];
                hs.split(sk, rk);

                auto ps_profile = make_profile();
                session_mgr_.add(peer.allowed_ip,
                                 std::make_shared<Session>(sk, rk),
                                 server_addr_, server_addr_len_);
                // Attach profile to peer session
                auto ps = session_mgr_.find_by_id(peer.allowed_ip);
                if (ps) ps->profile = ps_profile;

                routing_table_.add(peer.allowed_ip, peer.allowed_ip);
                sodium_memzero(sk, 32);
                sodium_memzero(rk, 32);

                tv = {0, 0};
                setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                return true;
            }
        }

    retry:
        if (attempt < 2) {
            std::cout << "retrying handshake..." << std::endl;
            sendto(udp_fd_, send_buf, send_len, 0,
                   reinterpret_cast<struct sockaddr*>(&server_addr_),
                   server_addr_len_);
        }
    }

    std::cerr << "error: handshake timed out" << std::endl;
    return false;
}

bool VpnDaemon::handle_handshake(const uint8_t* buf, ssize_t n,
                                 struct sockaddr_in& from, socklen_t from_len) {
    auto profile = make_profile();

    // Unwrap Noise msg1 from TLS ClientHello or raw format
    uint8_t noise_msg1[128];
    size_t noise_msg1_len;

    if (profile) {
        if (!profile->unwrap_handshake(noise_msg1, &noise_msg1_len,
                                       buf, n, false))
            return false;
    } else {
        std::memcpy(noise_msg1, buf + 1, n - 1);
        noise_msg1_len = n - 1;
    }

    NoiseHandshake hs(NoiseHandshake::Role::RESPONDER,
                      key_store_.private_key(),
                      key_store_.public_key(),
                      nullptr);

    if (!hs.read_message1(noise_msg1, noise_msg1_len)) {
        std::cerr << "error: invalid handshake msg1" << std::endl;
        return false;
    }

    const PeerInfo* matched = peer_registry_.find_by_public_key(
        hs.remote_static_public_key());
    if (!matched) {
        std::cerr << "error: unknown peer" << std::endl;
        return false;
    }

    uint8_t noise_msg2[128];
    size_t msg2_len;
    if (!hs.write_message2(noise_msg2, &msg2_len)) return false;

    // Wrap response as TLS ServerHello or raw format
    uint8_t send_buf[2048];
    size_t send_len;
    if (profile) {
        send_len = profile->wrap_handshake(send_buf, noise_msg2, msg2_len, false);
    } else {
        send_buf[0] = MSG_HANDSHAKE2;
        std::memcpy(send_buf + 1, noise_msg2, msg2_len);
        send_len = 1 + msg2_len;
    }

    sendto(udp_fd_, send_buf, send_len, 0,
           reinterpret_cast<struct sockaddr*>(&from), from_len);

    uint8_t sk[32], rk[32];
    hs.split(sk, rk);

    auto existing = session_mgr_.find_by_id(matched->allowed_ip);
    if (existing) {
        session_mgr_.update_session(matched->allowed_ip,
                                    std::make_shared<Session>(sk, rk),
                                    false);
        session_mgr_.update_addr(matched->allowed_ip, from, from_len);
        existing->profile = profile;
    } else {
        session_mgr_.add(matched->allowed_ip,
                         std::make_shared<Session>(sk, rk),
                         from, from_len);
        auto ps = session_mgr_.find_by_id(matched->allowed_ip);
        if (ps) ps->profile = profile;
        routing_table_.add(matched->allowed_ip, matched->allowed_ip);
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
// Rekey (client-initiated)
// ---------------------------------------------------------------------------

void VpnDaemon::initiate_rekey(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(rekey_mutex_);
    if (pending_rekey_) return;

    const PeerInfo* pi = peer_registry_.find_by_allowed_ip(peer_id);
    if (!pi) return;

    auto hs = std::make_unique<NoiseHandshake>(
        NoiseHandshake::Role::INITIATOR,
        key_store_.private_key(),
        key_store_.public_key(),
        pi->public_key);

    uint8_t noise_buf[128], send_buf[2048];
    size_t noise_len;
    if (!hs->write_message1(noise_buf, &noise_len)) return;

    auto ps = session_mgr_.find_by_id(peer_id);
    if (!ps) return;

    size_t send_len;
    if (ps->profile) {
        auto rekey_profile = make_profile();
        send_len = rekey_profile->wrap_handshake(send_buf, noise_buf, noise_len, true);
    } else {
        send_buf[0] = MSG_HANDSHAKE1;
        std::memcpy(send_buf + 1, noise_buf, noise_len);
        send_len = 1 + noise_len;
    }

    sendto(udp_fd_, send_buf, send_len, 0,
           reinterpret_cast<struct sockaddr*>(&ps->addr), ps->addr_len);

    pending_rekey_ = std::move(hs);
    rekey_peer_id_ = peer_id;
    std::cout << "rekey initiated for " << peer_id << std::endl;
}

// ---------------------------------------------------------------------------
// Data forwarding
// ---------------------------------------------------------------------------

void VpnDaemon::tun_to_udp() {
    uint8_t enc_buf[Packet::MAX_SIZE + Session::OVERHEAD + 1];
    uint8_t send_buf[8192];
    struct pollfd pfd;
    pfd.fd = tun_.fd();
    pfd.events = POLLIN;

    while (running_) {
        int ret = poll(&pfd, 1, 500);
        if (ret <= 0) continue;

        Packet pkt;
        if (!tun_.read_packet(pkt)) break;

        std::shared_ptr<PeerSession> ps;

        if (role_ == Config::Role::CLIENT) {
            auto& pi = peer_registry_.all();
            if (!pi.empty())
                ps = session_mgr_.find_by_id(pi[0].allowed_ip);
        } else {
            struct in_addr dst;
            dst.s_addr = pkt.get_dest_ip();
            char dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));
            std::string peer_id = routing_table_.resolve(dst_str);
            if (!peer_id.empty())
                ps = session_mgr_.find_by_id(peer_id);
        }

        if (!ps) continue;
        auto send_sess = ps->send_session();
        if (!send_sess) continue;

        // Encrypt
        size_t enc_len;
        if (!send_sess->encrypt(enc_buf, &enc_len, pkt.data(), pkt.length()))
            continue;

        // Wrap in TLS record or raw format
        size_t send_len;
        if (ps->profile) {
            send_len = ps->profile->wrap(send_buf, enc_buf, enc_len);
        } else {
            send_buf[0] = MSG_DATA;
            std::memcpy(send_buf + 1, enc_buf, enc_len);
            send_len = 1 + enc_len;
        }

        sendto(udp_fd_, send_buf, send_len, 0,
               reinterpret_cast<struct sockaddr*>(&ps->addr), ps->addr_len);
    }
}

void VpnDaemon::udp_to_tun() {
    uint8_t buf[8192];
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

        uint8_t first_byte = buf[0];

        // Detect message type: TLS content types (0x14-0x17) or raw (1-3)
        bool is_tls_handshake = (first_byte == TlsRecordBuilder::CONTENT_HANDSHAKE);
        bool is_tls_data = (first_byte == TlsRecordBuilder::CONTENT_APP_DATA);
        bool is_raw_hs1 = (first_byte == MSG_HANDSHAKE1);
        bool is_raw_hs2 = (first_byte == MSG_HANDSHAKE2);
        bool is_raw_data = (first_byte == MSG_DATA);

        // Server: accept handshakes (TLS or raw)
        if ((is_tls_handshake || is_raw_hs1) && role_ == Config::Role::SERVER) {
            handle_handshake(buf, n, from, from_len);
            continue;
        }

        // Client: complete pending rekey (TLS or raw)
        if ((is_tls_handshake || is_raw_hs2) && role_ == Config::Role::CLIENT) {
            std::lock_guard<std::mutex> lock(rekey_mutex_);
            if (pending_rekey_) {
                uint8_t noise_msg2[128];
                size_t noise_len;
                bool ok = false;

                if (is_tls_handshake) {
                    TlsProfile tmp;
                    ok = tmp.unwrap_handshake(noise_msg2, &noise_len,
                                              buf, n, true);
                } else {
                    std::memcpy(noise_msg2, buf + 1, n - 1);
                    noise_len = n - 1;
                    ok = true;
                }

                if (ok && pending_rekey_->read_message2(noise_msg2, noise_len)) {
                    uint8_t sk[32], rk[32];
                    pending_rekey_->split(sk, rk);
                    session_mgr_.update_session(rekey_peer_id_,
                                                std::make_shared<Session>(sk, rk),
                                                true);
                    sodium_memzero(sk, 32);
                    sodium_memzero(rk, 32);
                    std::cout << "rekey completed for "
                              << rekey_peer_id_ << std::endl;
                }
                pending_rekey_.reset();
            }
            continue;
        }

        if (!is_tls_data && !is_raw_data) continue;

        // Find peer session
        std::shared_ptr<PeerSession> ps;
        if (role_ == Config::Role::CLIENT) {
            auto& pi = peer_registry_.all();
            if (!pi.empty())
                ps = session_mgr_.find_by_id(pi[0].allowed_ip);
        } else {
            ps = session_mgr_.find_by_addr(from);
        }
        if (!ps) continue;

        // Unwrap TLS record or strip raw header
        uint8_t enc_data[8192];
        size_t enc_len;

        if (ps->profile && is_tls_data) {
            if (!ps->profile->unwrap(enc_data, &enc_len, buf, n))
                continue;
        } else if (is_raw_data) {
            std::memcpy(enc_data, buf + 1, n - 1);
            enc_len = n - 1;
        } else {
            continue;
        }

        // Decrypt
        uint8_t plaintext[2048];
        size_t pt_len;
        if (!ps->try_decrypt(plaintext, &pt_len, enc_data, enc_len))
            continue;

        Packet pkt;
        std::memcpy(pkt.data(), plaintext, pt_len);
        pkt.set_length(pt_len);
        tun_.write_packet(pkt);
    }
}
