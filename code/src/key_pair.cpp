#include "key_pair.h"

#include <cstring>
#include <sodium.h>

KeyPair::KeyPair() {
    std::memset(pub_, 0, KEY_SIZE);
    std::memset(priv_, 0, KEY_SIZE);
}

KeyPair::~KeyPair() {
    zeroize();
}

KeyPair::KeyPair(KeyPair&& other) noexcept {
    std::memcpy(pub_, other.pub_, KEY_SIZE);
    std::memcpy(priv_, other.priv_, KEY_SIZE);
    other.zeroize();
}

KeyPair& KeyPair::operator=(KeyPair&& other) noexcept {
    if (this != &other) {
        zeroize();
        std::memcpy(pub_, other.pub_, KEY_SIZE);
        std::memcpy(priv_, other.priv_, KEY_SIZE);
        other.zeroize();
    }
    return *this;
}

KeyPair KeyPair::generate() {
    KeyPair kp;
    crypto_box_keypair(kp.pub_, kp.priv_);
    return kp;
}

bool KeyPair::is_valid() const {
    uint8_t zero[KEY_SIZE]{};
    return sodium_memcmp(priv_, zero, KEY_SIZE) != 0;
}

void KeyPair::zeroize() {
    sodium_memzero(pub_, KEY_SIZE);
    sodium_memzero(priv_, KEY_SIZE);
}
