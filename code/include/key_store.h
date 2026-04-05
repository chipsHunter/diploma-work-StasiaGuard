#pragma once

#include "key_pair.h"

#include <string>

class KeyStore {
public:
    KeyStore();
    ~KeyStore();

    KeyStore(const KeyStore&) = delete;
    KeyStore& operator=(const KeyStore&) = delete;

    bool load_private_key(const std::string& path);

    const KeyPair& local_keypair() const { return local_keypair_; }
    const uint8_t* private_key() const { return local_keypair_.private_key(); }
    const uint8_t* public_key() const { return local_keypair_.public_key(); }

private:
    KeyPair local_keypair_;
};
