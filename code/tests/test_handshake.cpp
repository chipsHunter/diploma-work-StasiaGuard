#include "crypto_engine.h"
#include "key_pair.h"
#include "noise_handshake.h"
#include "session.h"

#include <cassert>
#include <cstring>
#include <iostream>

int main() {
    assert(CryptoEngine::init());
    std::cout << "Noise_IK handshake + Session tests:\n";

    // Generate static keys for both sides
    KeyPair server_static = KeyPair::generate();
    KeyPair client_static = KeyPair::generate();

    // Initiator (client) knows responder's (server's) static key
    NoiseHandshake initiator(NoiseHandshake::Role::INITIATOR,
                             client_static.private_key(),
                             client_static.public_key(),
                             server_static.public_key());

    NoiseHandshake responder(NoiseHandshake::Role::RESPONDER,
                             server_static.private_key(),
                             server_static.public_key(),
                             nullptr);

    // Message 1: initiator → responder
    uint8_t msg1[NoiseHandshake::MSG1_SIZE];
    size_t msg1_len;
    assert(initiator.write_message1(msg1, &msg1_len));
    assert(msg1_len == NoiseHandshake::MSG1_SIZE);
    assert(responder.read_message1(msg1, msg1_len));

    // Responder learned initiator's static key
    assert(std::memcmp(responder.remote_static_public_key(),
                       client_static.public_key(), 32) == 0);
    std::cout << "  msg1 (e, es, s, ss): PASS\n";

    // Message 2: responder → initiator
    uint8_t msg2[NoiseHandshake::MSG2_SIZE];
    size_t msg2_len;
    assert(responder.write_message2(msg2, &msg2_len));
    assert(msg2_len == NoiseHandshake::MSG2_SIZE);
    assert(initiator.read_message2(msg2, msg2_len));
    std::cout << "  msg2 (e, ee, se): PASS\n";

    // Split: derive transport keys
    uint8_t i_send[32], i_recv[32], r_send[32], r_recv[32];
    initiator.split(i_send, i_recv);
    responder.split(r_send, r_recv);

    assert(std::memcmp(i_send, r_recv, 32) == 0);
    assert(std::memcmp(i_recv, r_send, 32) == 0);
    std::cout << "  split keys match: PASS\n";

    // Create sessions
    Session client_session(i_send, i_recv);
    Session server_session(r_send, r_recv);

    // Client → Server
    const char* msg = "hello from client";
    size_t msg_len = std::strlen(msg);
    uint8_t encrypted[256], decrypted[256];
    size_t enc_len, dec_len;

    assert(client_session.encrypt(encrypted, &enc_len,
        reinterpret_cast<const uint8_t*>(msg), msg_len));
    assert(server_session.decrypt(decrypted, &dec_len, encrypted, enc_len));
    assert(dec_len == msg_len);
    assert(std::memcmp(decrypted, msg, msg_len) == 0);
    std::cout << "  client -> server message: PASS\n";

    // Server → Client
    const char* reply = "hello from server";
    size_t reply_len = std::strlen(reply);
    assert(server_session.encrypt(encrypted, &enc_len,
        reinterpret_cast<const uint8_t*>(reply), reply_len));
    assert(client_session.decrypt(decrypted, &dec_len, encrypted, enc_len));
    assert(dec_len == reply_len);
    assert(std::memcmp(decrypted, reply, reply_len) == 0);
    std::cout << "  server -> client message: PASS\n";

    // Replay attack: resend the same encrypted packet
    assert(!client_session.decrypt(decrypted, &dec_len, encrypted, enc_len));
    std::cout << "  replay attack rejected: PASS\n";

    // Tampered packet
    assert(server_session.encrypt(encrypted, &enc_len,
        reinterpret_cast<const uint8_t*>("test"), 4));
    encrypted[10] ^= 0xff;
    assert(!client_session.decrypt(decrypted, &dec_len, encrypted, enc_len));
    std::cout << "  tampered packet rejected: PASS\n";

    // Rekey timer (just verify the API)
    assert(!client_session.should_rekey());
    std::cout << "  should_rekey() = false (just created): PASS\n";

    std::cout << "All handshake + session tests passed.\n";
    return 0;
}
