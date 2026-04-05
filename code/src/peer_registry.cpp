#include "peer_registry.h"

#include <cstring>

void PeerRegistry::load(const std::vector<PeerInfo>& peers) {
    peers_ = peers;
}

const PeerInfo* PeerRegistry::find_by_public_key(const uint8_t* key) const {
    for (const auto& p : peers_) {
        if (std::memcmp(p.public_key, key, 32) == 0)
            return &p;
    }
    return nullptr;
}

const PeerInfo* PeerRegistry::find_by_allowed_ip(const std::string& ip) const {
    for (const auto& p : peers_) {
        if (p.allowed_ip == ip)
            return &p;
    }
    return nullptr;
}
