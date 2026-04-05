#pragma once

#include <cstddef>
#include <cstdint>

class KeyPair {
public:
    static constexpr size_t KEY_SIZE = 32;

    KeyPair();
    ~KeyPair();

    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;

    KeyPair(KeyPair&& other) noexcept;
    KeyPair& operator=(KeyPair&& other) noexcept;

    static KeyPair generate();
    static KeyPair from_private_key(const uint8_t* priv);

    const uint8_t* public_key() const { return pub_; }
    const uint8_t* private_key() const { return priv_; }

    bool is_valid() const;
    void zeroize();

private:
    uint8_t pub_[KEY_SIZE];
    uint8_t priv_[KEY_SIZE];
};
