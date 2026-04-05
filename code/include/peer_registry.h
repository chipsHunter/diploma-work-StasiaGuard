#pragma once

#include "peer_info.h"

#include <cstdint>
#include <string>
#include <vector>

class PeerRegistry {
public:
    void load(const std::vector<PeerInfo>& peers);

    const PeerInfo* find_by_public_key(const uint8_t* key) const;
    const PeerInfo* find_by_allowed_ip(const std::string& ip) const;

    const std::vector<PeerInfo>& all() const { return peers_; }
    size_t size() const { return peers_.size(); }

private:
    std::vector<PeerInfo> peers_;
};
