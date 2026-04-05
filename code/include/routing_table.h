#pragma once

#include <map>
#include <mutex>
#include <string>

class RoutingTable {
public:
    void add(const std::string& dest_ip, const std::string& peer_id);
    void remove(const std::string& dest_ip);
    std::string resolve(const std::string& dest_ip) const;

private:
    std::map<std::string, std::string> routes_;
    mutable std::mutex mutex_;
};
