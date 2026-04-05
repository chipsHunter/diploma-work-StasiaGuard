#include "session_manager.h"

#include <iostream>

SessionManager::SessionManager() : timer_running_(false) {}

SessionManager::~SessionManager() {
    stop_rekey_timer();
}

void SessionManager::set_rekey_callback(RekeyCallback cb) {
    rekey_callback_ = std::move(cb);
}

void SessionManager::start_rekey_timer() {
    timer_running_ = true;
    rekey_thread_ = std::thread(&SessionManager::rekey_loop, this);
}

void SessionManager::stop_rekey_timer() {
    timer_running_ = false;
    if (rekey_thread_.joinable())
        rekey_thread_.join();
}

void SessionManager::add(const std::string& peer_id,
                         std::shared_ptr<Session> session,
                         const struct sockaddr_in& addr, socklen_t addr_len) {
    auto ps = std::make_shared<PeerSession>();
    ps->session = std::move(session);
    ps->addr = addr;
    ps->addr_len = addr_len;

    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[peer_id] = std::move(ps);
}

void SessionManager::update_session(const std::string& peer_id,
                                    std::shared_ptr<Session> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end())
        it->second->session = std::move(session);
}

void SessionManager::update_addr(const std::string& peer_id,
                                 const struct sockaddr_in& addr,
                                 socklen_t addr_len) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end()) {
        it->second->addr = addr;
        it->second->addr_len = addr_len;
    }
}

void SessionManager::remove(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(peer_id);
}

std::shared_ptr<PeerSession> SessionManager::find_by_id(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(peer_id);
    return (it != sessions_.end()) ? it->second : nullptr;
}

std::shared_ptr<PeerSession> SessionManager::find_by_addr(
        const struct sockaddr_in& addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, ps] : sessions_) {
        if (ps->addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
            ps->addr.sin_port == addr.sin_port)
            return ps;
    }
    return nullptr;
}

size_t SessionManager::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

void SessionManager::rekey_loop() {
    while (timer_running_) {
        for (int i = 0; i < 10 && timer_running_; i++)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!timer_running_) break;

        std::vector<std::string> need_rekey;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [id, ps] : sessions_) {
                if (ps->session && ps->session->should_rekey())
                    need_rekey.push_back(id);
            }
        }

        for (const auto& id : need_rekey) {
            if (rekey_callback_)
                rekey_callback_(id);
        }
    }
}
