#pragma once

#include <cstddef>
#include <cstdint>

class CryptoEngine {
public:
    static constexpr size_t KEY_SIZE  = 32;
    static constexpr size_t NONCE_SIZE = 24;
    static constexpr size_t TAG_SIZE  = 16;
    static constexpr size_t DH_SIZE   = 32;
    static constexpr size_t HASH_SIZE = 32;

    static bool init();

    // XChaCha20-Poly1305 AEAD
    static bool encrypt(uint8_t* ciphertext,
                        const uint8_t* plaintext, size_t plaintext_len,
                        const uint8_t* ad, size_t ad_len,
                        const uint8_t* nonce,
                        const uint8_t* key);

    static bool decrypt(uint8_t* plaintext,
                        const uint8_t* ciphertext, size_t ciphertext_len,
                        const uint8_t* ad, size_t ad_len,
                        const uint8_t* nonce,
                        const uint8_t* key);

    // X25519 Diffie-Hellman
    static bool dh(uint8_t* shared_secret,
                   const uint8_t* private_key,
                   const uint8_t* public_key);

    // Noise-style HKDF (out3 may be nullptr for 2-output variant)
    static void hkdf(uint8_t* out1, uint8_t* out2, uint8_t* out3,
                     const uint8_t* chaining_key,
                     const uint8_t* input_key_material, size_t ikm_len);

    // SHA-256
    static void hash(uint8_t* output,
                     const uint8_t* input, size_t input_len);

    // HMAC-SHA-256
    static void hmac(uint8_t* output,
                     const uint8_t* key, size_t key_len,
                     const uint8_t* data, size_t data_len);

private:
    CryptoEngine() = delete;
};
