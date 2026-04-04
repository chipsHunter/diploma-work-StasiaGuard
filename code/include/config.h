#pragma once

#include "peer_info.h"

#include <cstdint>
#include <string>
#include <vector>

class Config {
public:
    enum class Role { SERVER, CLIENT };

    bool load(const std::string& path);

    Role role() const { return role_; }
    uint16_t listen_port() const { return listen_port_; }
    const std::string& tun_ip() const { return tun_ip_; }
    int tun_mask() const { return tun_mask_; }
    const std::string& private_key_path() const { return private_key_path_; }
    const std::vector<PeerInfo>& peers() const { return peers_; }

    static bool base64_decode(const std::string& b64,
                              uint8_t* out, size_t expected_len);
    static std::string base64_encode(const uint8_t* data, size_t len);

private:
    Role role_ = Role::CLIENT;
    uint16_t listen_port_ = 51820;
    std::string tun_ip_;
    int tun_mask_ = 24;
    std::string private_key_path_;
    std::vector<PeerInfo> peers_;
};
