#include "routing_table.h"

void RoutingTable::add(const std::string& dest_ip, const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    routes_[dest_ip] = peer_id;
}

void RoutingTable::remove(const std::string& dest_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    routes_.erase(dest_ip);
}

std::string RoutingTable::resolve(const std::string& dest_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = routes_.find(dest_ip);
    return (it != routes_.end()) ? it->second : "";
}
