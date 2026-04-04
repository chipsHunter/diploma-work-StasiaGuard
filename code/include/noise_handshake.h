#pragma once

#include "key_pair.h"
#include <cstddef>
#include <cstdint>

class NoiseHandshake {
public:
    enum class Role { INITIATOR, RESPONDER };

    // msg1: e(32) + encrypted_s(32+16) + payload_tag(16) = 96
    static constexpr size_t MSG1_SIZE = 96;
    // msg2: e(32) + payload_tag(16) = 48
    static constexpr size_t MSG2_SIZE = 48;

    // For initiator: peer_static_pub = responder's known public key
    // For responder: peer_static_pub = nullptr (learned from msg1)
    NoiseHandshake(Role role,
                   const uint8_t* local_static_private,
                   const uint8_t* local_static_public,
                   const uint8_t* peer_static_pub);

    ~NoiseHandshake();

    NoiseHandshake(const NoiseHandshake&) = delete;
    NoiseHandshake& operator=(const NoiseHandshake&) = delete;

    bool write_message1(uint8_t* out, size_t* out_len);
    bool read_message1(const uint8_t* msg, size_t msg_len);
    bool write_message2(uint8_t* out, size_t* out_len);
    bool read_message2(const uint8_t* msg, size_t msg_len);

    void split(uint8_t* send_key, uint8_t* recv_key);

    const uint8_t* remote_static_public_key() const { return remote_static_pub_; }
    const uint8_t* handshake_hash() const { return h_; }

private:
    static constexpr size_t KEY_LEN  = 32;
    static constexpr size_t HASH_LEN = 32;
    static constexpr size_t TAG_LEN  = 16;

    void mix_hash(const uint8_t* data, size_t len);
    void mix_key(const uint8_t* ikm, size_t ikm_len);
    bool encrypt_and_hash(uint8_t* out, const uint8_t* plaintext, size_t pt_len);
    bool decrypt_and_hash(uint8_t* out, const uint8_t* ciphertext, size_t ct_len);
    void build_nonce(uint8_t* nonce, uint64_t counter);

    Role role_;
    uint8_t ck_[HASH_LEN];
    uint8_t h_[HASH_LEN];
    uint8_t k_[KEY_LEN];
    bool has_key_;
    uint64_t n_;

    const uint8_t* local_static_priv_;
    const uint8_t* local_static_pub_;

    KeyPair local_ephemeral_;

    uint8_t remote_static_pub_[KEY_LEN];
    uint8_t remote_ephemeral_pub_[KEY_LEN];
};
