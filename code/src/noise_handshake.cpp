#include "noise_handshake.h"
#include "crypto_engine.h"

#include <cstring>
#include <sodium.h>

static constexpr const char* PROTOCOL_NAME = "Noise_IK_25519_XChaChaPoly_SHA256";

NoiseHandshake::NoiseHandshake(Role role,
                               const uint8_t* local_static_private,
                               const uint8_t* local_static_public,
                               const uint8_t* peer_static_pub)
    : role_(role)
    , has_key_(false)
    , n_(0)
    , local_static_priv_(local_static_private)
    , local_static_pub_(local_static_public) {

    std::memset(remote_static_pub_, 0, KEY_LEN);
    std::memset(remote_ephemeral_pub_, 0, KEY_LEN);
    std::memset(k_, 0, KEY_LEN);

    // h = HASH(protocol_name), ck = h
    CryptoEngine::hash(h_,
                       reinterpret_cast<const uint8_t*>(PROTOCOL_NAME),
                       std::strlen(PROTOCOL_NAME));
    std::memcpy(ck_, h_, HASH_LEN);

    // Pre-message pattern: <- s (responder's static key is pre-known)
    if (role_ == Role::INITIATOR) {
        std::memcpy(remote_static_pub_, peer_static_pub, KEY_LEN);
        mix_hash(peer_static_pub, KEY_LEN);
    } else {
        mix_hash(local_static_pub_, KEY_LEN);
    }
}

NoiseHandshake::~NoiseHandshake() {
    sodium_memzero(ck_, HASH_LEN);
    sodium_memzero(h_, HASH_LEN);
    sodium_memzero(k_, KEY_LEN);
}

// ---------------------------------------------------------------------------
// Message 1: initiator -> responder  (e, es, s, ss)
// ---------------------------------------------------------------------------

bool NoiseHandshake::write_message1(uint8_t* out, size_t* out_len) {
    local_ephemeral_ = KeyPair::generate();

    // e: send ephemeral public key in the clear
    std::memcpy(out, local_ephemeral_.public_key(), KEY_LEN);
    mix_hash(local_ephemeral_.public_key(), KEY_LEN);

    // es: DH(initiator_ephemeral, responder_static)
    uint8_t dh_out[KEY_LEN];
    CryptoEngine::dh(dh_out, local_ephemeral_.private_key(), remote_static_pub_);
    mix_key(dh_out, KEY_LEN);

    // s: encrypt and send initiator's static public key
    if (!encrypt_and_hash(out + 32, local_static_pub_, KEY_LEN))
        return false;

    // ss: DH(initiator_static, responder_static)
    CryptoEngine::dh(dh_out, local_static_priv_, remote_static_pub_);
    mix_key(dh_out, KEY_LEN);

    // empty payload
    if (!encrypt_and_hash(out + 32 + KEY_LEN + TAG_LEN, nullptr, 0))
        return false;

    sodium_memzero(dh_out, KEY_LEN);
    *out_len = MSG1_SIZE;
    return true;
}

bool NoiseHandshake::read_message1(const uint8_t* msg, size_t msg_len) {
    if (msg_len != MSG1_SIZE) return false;

    // e: read initiator's ephemeral public key
    std::memcpy(remote_ephemeral_pub_, msg, KEY_LEN);
    mix_hash(remote_ephemeral_pub_, KEY_LEN);

    // es: DH(responder_static, initiator_ephemeral)
    uint8_t dh_out[KEY_LEN];
    CryptoEngine::dh(dh_out, local_static_priv_, remote_ephemeral_pub_);
    mix_key(dh_out, KEY_LEN);

    // s: decrypt initiator's static public key
    if (!decrypt_and_hash(remote_static_pub_, msg + 32, KEY_LEN + TAG_LEN)) {
        sodium_memzero(dh_out, KEY_LEN);
        return false;
    }

    // ss: DH(responder_static, initiator_static)
    CryptoEngine::dh(dh_out, local_static_priv_, remote_static_pub_);
    mix_key(dh_out, KEY_LEN);

    // empty payload
    uint8_t dummy[1];
    if (!decrypt_and_hash(dummy, msg + 32 + KEY_LEN + TAG_LEN, TAG_LEN)) {
        sodium_memzero(dh_out, KEY_LEN);
        return false;
    }

    sodium_memzero(dh_out, KEY_LEN);
    return true;
}

// ---------------------------------------------------------------------------
// Message 2: responder -> initiator  (e, ee, se)
// ---------------------------------------------------------------------------

bool NoiseHandshake::write_message2(uint8_t* out, size_t* out_len) {
    local_ephemeral_ = KeyPair::generate();

    // e: send ephemeral public key
    std::memcpy(out, local_ephemeral_.public_key(), KEY_LEN);
    mix_hash(local_ephemeral_.public_key(), KEY_LEN);

    // ee: DH(responder_ephemeral, initiator_ephemeral)
    uint8_t dh_out[KEY_LEN];
    CryptoEngine::dh(dh_out, local_ephemeral_.private_key(), remote_ephemeral_pub_);
    mix_key(dh_out, KEY_LEN);

    // se: DH(responder_ephemeral, initiator_static)
    CryptoEngine::dh(dh_out, local_ephemeral_.private_key(), remote_static_pub_);
    mix_key(dh_out, KEY_LEN);

    // empty payload
    if (!encrypt_and_hash(out + KEY_LEN, nullptr, 0))
        return false;

    sodium_memzero(dh_out, KEY_LEN);
    *out_len = MSG2_SIZE;
    return true;
}

bool NoiseHandshake::read_message2(const uint8_t* msg, size_t msg_len) {
    if (msg_len != MSG2_SIZE) return false;

    // e: read responder's ephemeral public key
    std::memcpy(remote_ephemeral_pub_, msg, KEY_LEN);
    mix_hash(remote_ephemeral_pub_, KEY_LEN);

    // ee: DH(initiator_ephemeral, responder_ephemeral)
    uint8_t dh_out[KEY_LEN];
    CryptoEngine::dh(dh_out, local_ephemeral_.private_key(), remote_ephemeral_pub_);
    mix_key(dh_out, KEY_LEN);

    // se: DH(initiator_static, responder_ephemeral)
    CryptoEngine::dh(dh_out, local_static_priv_, remote_ephemeral_pub_);
    mix_key(dh_out, KEY_LEN);

    // empty payload
    uint8_t dummy[1];
    if (!decrypt_and_hash(dummy, msg + KEY_LEN, TAG_LEN)) {
        sodium_memzero(dh_out, KEY_LEN);
        return false;
    }

    sodium_memzero(dh_out, KEY_LEN);
    return true;
}

// ---------------------------------------------------------------------------
// Split — derive transport keys
// ---------------------------------------------------------------------------

void NoiseHandshake::split(uint8_t* send_key, uint8_t* recv_key) {
    uint8_t k1[KEY_LEN], k2[KEY_LEN];
    uint8_t zerolen = 0;
    CryptoEngine::hkdf(k1, k2, nullptr, ck_, &zerolen, 0);

    if (role_ == Role::INITIATOR) {
        std::memcpy(send_key, k1, KEY_LEN);
        std::memcpy(recv_key, k2, KEY_LEN);
    } else {
        std::memcpy(send_key, k2, KEY_LEN);
        std::memcpy(recv_key, k1, KEY_LEN);
    }

    sodium_memzero(k1, KEY_LEN);
    sodium_memzero(k2, KEY_LEN);
}

// ---------------------------------------------------------------------------
// Noise primitives
// ---------------------------------------------------------------------------

void NoiseHandshake::mix_hash(const uint8_t* data, size_t len) {
    uint8_t buf[HASH_LEN + 1500];
    std::memcpy(buf, h_, HASH_LEN);
    std::memcpy(buf + HASH_LEN, data, len);
    CryptoEngine::hash(h_, buf, HASH_LEN + len);
}

void NoiseHandshake::mix_key(const uint8_t* ikm, size_t ikm_len) {
    uint8_t temp_k[KEY_LEN];
    CryptoEngine::hkdf(ck_, temp_k, nullptr, ck_, ikm, ikm_len);
    std::memcpy(k_, temp_k, KEY_LEN);
    has_key_ = true;
    n_ = 0;
    sodium_memzero(temp_k, KEY_LEN);
}

bool NoiseHandshake::encrypt_and_hash(uint8_t* out,
                                      const uint8_t* plaintext, size_t pt_len) {
    if (has_key_) {
        uint8_t nonce[CryptoEngine::NONCE_SIZE];
        build_nonce(nonce, n_);
        if (!CryptoEngine::encrypt(out, plaintext, pt_len,
                                   h_, HASH_LEN, nonce, k_))
            return false;
        n_++;
        mix_hash(out, pt_len + TAG_LEN);
    } else {
        if (pt_len > 0) std::memcpy(out, plaintext, pt_len);
        mix_hash(out, pt_len);
    }
    return true;
}

bool NoiseHandshake::decrypt_and_hash(uint8_t* out,
                                      const uint8_t* ciphertext, size_t ct_len) {
    if (has_key_) {
        uint8_t nonce[CryptoEngine::NONCE_SIZE];
        build_nonce(nonce, n_);
        if (!CryptoEngine::decrypt(out, ciphertext, ct_len,
                                   h_, HASH_LEN, nonce, k_))
            return false;
        n_++;
        mix_hash(ciphertext, ct_len);
    } else {
        if (ct_len > 0) std::memcpy(out, ciphertext, ct_len);
        mix_hash(ciphertext, ct_len);
    }
    return true;
}

void NoiseHandshake::build_nonce(uint8_t* nonce, uint64_t counter) {
    std::memset(nonce, 0, CryptoEngine::NONCE_SIZE);
    for (int i = 0; i < 8; i++)
        nonce[16 + i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xff);
}
