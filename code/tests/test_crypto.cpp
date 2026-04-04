#include "crypto_engine.h"
#include "key_pair.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <sodium.h>

static void test_encrypt_decrypt() {
    uint8_t key[CryptoEngine::KEY_SIZE];
    uint8_t nonce[CryptoEngine::NONCE_SIZE];
    randombytes_buf(key, sizeof(key));
    randombytes_buf(nonce, sizeof(nonce));

    const char* msg = "hello vpn";
    size_t msg_len = std::strlen(msg);

    uint8_t ct[128];
    assert(CryptoEngine::encrypt(ct,
        reinterpret_cast<const uint8_t*>(msg), msg_len,
        nullptr, 0, nonce, key));

    uint8_t pt[128];
    assert(CryptoEngine::decrypt(pt, ct, msg_len + CryptoEngine::TAG_SIZE,
        nullptr, 0, nonce, key));

    assert(std::memcmp(pt, msg, msg_len) == 0);
    std::cout << "  encrypt/decrypt roundtrip: PASS\n";
}

static void test_tampered_ciphertext() {
    uint8_t key[CryptoEngine::KEY_SIZE];
    uint8_t nonce[CryptoEngine::NONCE_SIZE];
    randombytes_buf(key, sizeof(key));
    randombytes_buf(nonce, sizeof(nonce));

    const char* msg = "secret";
    size_t msg_len = std::strlen(msg);

    uint8_t ct[128];
    CryptoEngine::encrypt(ct,
        reinterpret_cast<const uint8_t*>(msg), msg_len,
        nullptr, 0, nonce, key);

    ct[0] ^= 0xff;

    uint8_t pt[128];
    assert(!CryptoEngine::decrypt(pt, ct, msg_len + CryptoEngine::TAG_SIZE,
        nullptr, 0, nonce, key));
    std::cout << "  tampered ciphertext rejected: PASS\n";
}

static void test_aead_with_ad() {
    uint8_t key[CryptoEngine::KEY_SIZE];
    uint8_t nonce[CryptoEngine::NONCE_SIZE];
    randombytes_buf(key, sizeof(key));
    randombytes_buf(nonce, sizeof(nonce));

    const char* msg = "payload";
    size_t msg_len = std::strlen(msg);
    const char* ad = "header";
    size_t ad_len = std::strlen(ad);

    uint8_t ct[128];
    CryptoEngine::encrypt(ct,
        reinterpret_cast<const uint8_t*>(msg), msg_len,
        reinterpret_cast<const uint8_t*>(ad), ad_len,
        nonce, key);

    // Decrypt with correct AD succeeds
    uint8_t pt[128];
    assert(CryptoEngine::decrypt(pt, ct, msg_len + CryptoEngine::TAG_SIZE,
        reinterpret_cast<const uint8_t*>(ad), ad_len,
        nonce, key));

    // Decrypt with wrong AD fails
    const char* bad_ad = "HEADER";
    assert(!CryptoEngine::decrypt(pt, ct, msg_len + CryptoEngine::TAG_SIZE,
        reinterpret_cast<const uint8_t*>(bad_ad), ad_len,
        nonce, key));
    std::cout << "  AEAD with associated data: PASS\n";
}

static void test_dh() {
    KeyPair a = KeyPair::generate();
    KeyPair b = KeyPair::generate();

    uint8_t shared_ab[CryptoEngine::DH_SIZE];
    uint8_t shared_ba[CryptoEngine::DH_SIZE];

    assert(CryptoEngine::dh(shared_ab, a.private_key(), b.public_key()));
    assert(CryptoEngine::dh(shared_ba, b.private_key(), a.public_key()));

    assert(std::memcmp(shared_ab, shared_ba, CryptoEngine::DH_SIZE) == 0);
    std::cout << "  DH key agreement: PASS\n";
}

static void test_hkdf() {
    uint8_t ck[CryptoEngine::HASH_SIZE];
    uint8_t ikm[CryptoEngine::HASH_SIZE];
    randombytes_buf(ck, sizeof(ck));
    randombytes_buf(ikm, sizeof(ikm));

    uint8_t out1a[32], out2a[32], out1b[32], out2b[32];
    CryptoEngine::hkdf(out1a, out2a, nullptr, ck, ikm, sizeof(ikm));
    CryptoEngine::hkdf(out1b, out2b, nullptr, ck, ikm, sizeof(ikm));

    assert(std::memcmp(out1a, out1b, 32) == 0);
    assert(std::memcmp(out2a, out2b, 32) == 0);
    assert(std::memcmp(out1a, out2a, 32) != 0);

    // 3-output variant
    uint8_t out3[32];
    CryptoEngine::hkdf(out1a, out2a, out3, ck, ikm, sizeof(ikm));
    assert(std::memcmp(out2a, out3, 32) != 0);
    std::cout << "  HKDF determinism and distinctness: PASS\n";
}

static void test_hash() {
    const char* data = "test";
    uint8_t h1[CryptoEngine::HASH_SIZE], h2[CryptoEngine::HASH_SIZE];
    CryptoEngine::hash(h1, reinterpret_cast<const uint8_t*>(data), 4);
    CryptoEngine::hash(h2, reinterpret_cast<const uint8_t*>(data), 4);
    assert(std::memcmp(h1, h2, CryptoEngine::HASH_SIZE) == 0);

    CryptoEngine::hash(h2, reinterpret_cast<const uint8_t*>("other"), 5);
    assert(std::memcmp(h1, h2, CryptoEngine::HASH_SIZE) != 0);
    std::cout << "  SHA-256 hash: PASS\n";
}

static void test_keypair() {
    KeyPair kp = KeyPair::generate();
    assert(kp.is_valid());

    KeyPair moved = std::move(kp);
    assert(moved.is_valid());
    assert(!kp.is_valid());

    moved.zeroize();
    assert(!moved.is_valid());
    std::cout << "  KeyPair generate/move/zeroize: PASS\n";
}

int main() {
    assert(CryptoEngine::init());
    std::cout << "CryptoEngine tests:\n";

    test_encrypt_decrypt();
    test_tampered_ciphertext();
    test_aead_with_ad();
    test_dh();
    test_hkdf();
    test_hash();
    test_keypair();

    std::cout << "All crypto tests passed.\n";
    return 0;
}
