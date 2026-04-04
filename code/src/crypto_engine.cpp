#include "crypto_engine.h"

#include <sodium.h>

bool CryptoEngine::init() {
    return sodium_init() >= 0;
}

bool CryptoEngine::encrypt(uint8_t* ciphertext,
                           const uint8_t* plaintext, size_t plaintext_len,
                           const uint8_t* ad, size_t ad_len,
                           const uint8_t* nonce,
                           const uint8_t* key) {
    unsigned long long clen;
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, &clen,
        plaintext, plaintext_len,
        ad, ad_len,
        nullptr, nonce, key) == 0;
}

bool CryptoEngine::decrypt(uint8_t* plaintext,
                           const uint8_t* ciphertext, size_t ciphertext_len,
                           const uint8_t* ad, size_t ad_len,
                           const uint8_t* nonce,
                           const uint8_t* key) {
    if (ciphertext_len < TAG_SIZE) return false;
    unsigned long long mlen;
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext, &mlen,
        nullptr,
        ciphertext, ciphertext_len,
        ad, ad_len,
        nonce, key) == 0;
}

bool CryptoEngine::dh(uint8_t* shared_secret,
                      const uint8_t* private_key,
                      const uint8_t* public_key) {
    return crypto_scalarmult(shared_secret, private_key, public_key) == 0;
}

void CryptoEngine::hkdf(uint8_t* out1, uint8_t* out2, uint8_t* out3,
                        const uint8_t* chaining_key,
                        const uint8_t* input_key_material, size_t ikm_len) {
    uint8_t temp_key[HASH_SIZE];
    hmac(temp_key, chaining_key, HASH_SIZE, input_key_material, ikm_len);

    // output1 = HMAC(temp_key, 0x01)
    uint8_t byte_val = 0x01;
    hmac(out1, temp_key, HASH_SIZE, &byte_val, 1);

    // output2 = HMAC(temp_key, output1 || 0x02)
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, temp_key, HASH_SIZE);
    crypto_auth_hmacsha256_update(&state, out1, HASH_SIZE);
    byte_val = 0x02;
    crypto_auth_hmacsha256_update(&state, &byte_val, 1);
    crypto_auth_hmacsha256_final(&state, out2);

    if (out3) {
        crypto_auth_hmacsha256_init(&state, temp_key, HASH_SIZE);
        crypto_auth_hmacsha256_update(&state, out2, HASH_SIZE);
        byte_val = 0x03;
        crypto_auth_hmacsha256_update(&state, &byte_val, 1);
        crypto_auth_hmacsha256_final(&state, out3);
    }

    sodium_memzero(temp_key, HASH_SIZE);
    sodium_memzero(&state, sizeof(state));
}

void CryptoEngine::hash(uint8_t* output,
                        const uint8_t* input, size_t input_len) {
    crypto_hash_sha256(output, input, input_len);
}

void CryptoEngine::hmac(uint8_t* output,
                        const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len) {
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    if (data_len > 0)
        crypto_auth_hmacsha256_update(&state, data, data_len);
    crypto_auth_hmacsha256_final(&state, output);
}
