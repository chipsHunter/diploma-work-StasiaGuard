#pragma once

#include <cstdint>
#include <string>

struct PeerInfo {
    uint8_t public_key[32]{};
    std::string endpoint;   // "ip:port" — empty for server-side peers
    std::string allowed_ip; // e.g. "10.0.0.2"
};
