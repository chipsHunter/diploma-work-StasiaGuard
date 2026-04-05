#pragma once

#include "session.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <thread>

struct PeerSession {
    std::shared_ptr<Session> session;       // current (recv always, send when confirmed)
    std::shared_ptr<Session> prev_session;  // previous (recv fallback, send until confirmed)
    bool send_confirmed = true;             // false on responder during rekey transition
    struct sockaddr_in addr{};
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Returns the session to use for encrypting outbound packets
    std::shared_ptr<Session> send_session() const {
        return send_confirmed ? session : prev_session;
    }

    // Try decrypting with current, then fallback to prev.
    // Returns true if decryption succeeded. Sets confirm_send=true
    // if current session succeeded (peer has switched).
    bool try_decrypt(uint8_t* out, size_t* out_len,
                     const uint8_t* ct, size_t ct_len);
};

class SessionManager {
public:
    using RekeyCallback = std::function<void(const std::string& peer_id)>;

    SessionManager();
    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    void set_rekey_callback(RekeyCallback cb);
    void start_rekey_timer();
    void stop_rekey_timer();

    void add(const std::string& peer_id, std::shared_ptr<Session> session,
             const struct sockaddr_in& addr, socklen_t addr_len);
    // initiator=true: caller is the handshake initiator → switch send immediately
    // initiator=false: caller is responder → delay send switch until confirmed
    void update_session(const std::string& peer_id,
                        std::shared_ptr<Session> session,
                        bool initiator = true);
    void update_addr(const std::string& peer_id,
                     const struct sockaddr_in& addr, socklen_t addr_len);
    void remove(const std::string& peer_id);

    std::shared_ptr<PeerSession> find_by_id(const std::string& peer_id);
    std::shared_ptr<PeerSession> find_by_addr(const struct sockaddr_in& addr);

    size_t count() const;

private:
    void rekey_loop();

    std::map<std::string, std::shared_ptr<PeerSession>> sessions_;
    mutable std::mutex mutex_;

    RekeyCallback rekey_callback_;
    std::thread rekey_thread_;
    std::atomic<bool> timer_running_;
};
