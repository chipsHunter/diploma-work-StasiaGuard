#include "session.h"
#include "crypto_engine.h"

#include <cstring>
#include <sodium.h>

Session::Session(const uint8_t* send_key, const uint8_t* recv_key)
    : send_nonce_(0)
    , created_at_(std::chrono::steady_clock::now()) {
    std::memcpy(send_key_, send_key, KEY_SIZE);
    std::memcpy(recv_key_, recv_key, KEY_SIZE);
}

Session::~Session() {
    sodium_memzero(send_key_, KEY_SIZE);
    sodium_memzero(recv_key_, KEY_SIZE);
}

bool Session::encrypt(uint8_t* out, size_t* out_len,
                      const uint8_t* plaintext, size_t pt_len) {
    uint64_t counter = send_nonce_.fetch_add(1);

    // Write counter as little-endian header
    std::memcpy(out, &counter, 8);

    uint8_t nonce[CryptoEngine::NONCE_SIZE];
    build_nonce(nonce, counter);

    if (!CryptoEngine::encrypt(out + 8, plaintext, pt_len,
                               nullptr, 0, nonce, send_key_))
        return false;

    *out_len = 8 + pt_len + CryptoEngine::TAG_SIZE;
    return true;
}

bool Session::decrypt(uint8_t* out, size_t* out_len,
                      const uint8_t* ciphertext, size_t ct_len) {
    if (ct_len < OVERHEAD) return false;

    uint64_t counter;
    std::memcpy(&counter, ciphertext, 8);

    uint8_t nonce[CryptoEngine::NONCE_SIZE];
    build_nonce(nonce, counter);

    size_t enc_len = ct_len - 8;
    if (!CryptoEngine::decrypt(out, ciphertext + 8, enc_len,
                               nullptr, 0, nonce, recv_key_))
        return false;

    // Anti-replay check only after successful authentication
    if (!anti_replay_.check_and_update(counter)) return false;

    *out_len = enc_len - CryptoEngine::TAG_SIZE;
    return true;
}

bool Session::should_rekey() const {
    auto elapsed = std::chrono::steady_clock::now() - created_at_;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    return seconds >= REKEY_AFTER_SECONDS;
}

void Session::build_nonce(uint8_t* nonce, uint64_t counter) {
    std::memset(nonce, 0, CryptoEngine::NONCE_SIZE);
    for (int i = 0; i < 8; i++)
        nonce[16 + i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xff);
}
