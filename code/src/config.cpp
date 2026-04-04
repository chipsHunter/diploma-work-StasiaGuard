#include "config.h"

#include <fstream>
#include <iostream>
#include <sodium.h>
#include <yaml-cpp/yaml.h>

bool Config::load(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        std::cerr << "error: cannot load config: " << e.what() << "\n";
        return false;
    }

    std::string role_str = root["role"].as<std::string>();
    if (role_str == "server")
        role_ = Role::SERVER;
    else if (role_str == "client")
        role_ = Role::CLIENT;
    else {
        std::cerr << "error: role must be 'server' or 'client'\n";
        return false;
    }

    listen_port_ = root["listen_port"].as<uint16_t>(51820);
    tun_ip_ = root["tun_ip"].as<std::string>();
    tun_mask_ = root["tun_mask"].as<int>(24);
    private_key_path_ = root["private_key_path"].as<std::string>();

    if (root["peers"]) {
        for (const auto& peer_node : root["peers"]) {
            PeerInfo peer;

            std::string b64_key = peer_node["public_key"].as<std::string>();
            if (!base64_decode(b64_key, peer.public_key, 32)) {
                std::cerr << "error: invalid peer public key\n";
                return false;
            }

            if (peer_node["endpoint"])
                peer.endpoint = peer_node["endpoint"].as<std::string>();

            peer.allowed_ip = peer_node["allowed_ip"].as<std::string>();
            peers_.push_back(peer);
        }
    }

    return true;
}

bool Config::base64_decode(const std::string& b64,
                           uint8_t* out, size_t expected_len) {
    size_t actual_len;
    if (sodium_base642bin(out, expected_len,
                          b64.c_str(), b64.size(),
                          " \t\n\r", &actual_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return false;
    return actual_len == expected_len;
}

std::string Config::base64_encode(const uint8_t* data, size_t len) {
    size_t b64_maxlen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string result(b64_maxlen, '\0');
    sodium_bin2base64(&result[0], b64_maxlen, data, len,
                      sodium_base64_VARIANT_ORIGINAL);
    // trim trailing null
    size_t pos = result.find('\0');
    if (pos != std::string::npos) result.resize(pos);
    return result;
}
