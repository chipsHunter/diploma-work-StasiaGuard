#pragma once

#include "anti_replay.h"
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

class Session {
public:
    static constexpr int REKEY_AFTER_SECONDS = 180;
    static constexpr size_t OVERHEAD = 24; // 8 (counter) + 16 (tag)

    Session(const uint8_t* send_key, const uint8_t* recv_key);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // out must hold at least pt_len + OVERHEAD bytes
    bool encrypt(uint8_t* out, size_t* out_len,
                 const uint8_t* plaintext, size_t pt_len);

    // out must hold at least ct_len - OVERHEAD bytes
    bool decrypt(uint8_t* out, size_t* out_len,
                 const uint8_t* ciphertext, size_t ct_len);

    bool should_rekey() const;

private:
    static constexpr size_t KEY_SIZE = 32;

    void build_nonce(uint8_t* nonce, uint64_t counter);

    uint8_t send_key_[KEY_SIZE];
    uint8_t recv_key_[KEY_SIZE];
    std::atomic<uint64_t> send_nonce_;
    AntiReplay anti_replay_;
    std::chrono::steady_clock::time_point created_at_;
};
