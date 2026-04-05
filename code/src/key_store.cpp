#include "key_store.h"
#include "config.h"

#include <fstream>
#include <iostream>
#include <sodium.h>

KeyStore::KeyStore() = default;

KeyStore::~KeyStore() = default;

bool KeyStore::load_private_key(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        std::cerr << "error: cannot open private key: " << path << std::endl;
        return false;
    }

    std::string b64;
    std::getline(f, b64);
    uint8_t priv[32];
    if (!Config::base64_decode(b64, priv, 32)) {
        std::cerr << "error: invalid private key format" << std::endl;
        return false;
    }

    local_keypair_ = KeyPair::from_private_key(priv);
    sodium_memzero(priv, 32);
    return true;
}
