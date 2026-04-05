#include "tls_profile.h"
#include "noise_handshake.h"
#include "padding_calculator.h"
#include "tls_record_builder.h"

#include <cstring>
#include <sodium.h>

TlsProfile::TlsProfile() : client_session_id_len_(0) {
    std::memset(client_session_id_, 0, sizeof(client_session_id_));
}

// ---------------------------------------------------------------------------
// Data wrapping: payload → TLS application_data record with padding
//
// Wire format of payload inside the TLS record:
//   [2 bytes: actual data length (big-endian)][data][random padding]
// ---------------------------------------------------------------------------

size_t TlsProfile::wrap(uint8_t* out,
                        const uint8_t* data, size_t data_len) {
    // 2-byte length prefix + data
    size_t inner_len = 2 + data_len;
    size_t padded = PaddingCalculator::calculate(inner_len);

    uint8_t payload[8192];
    payload[0] = static_cast<uint8_t>(data_len >> 8);
    payload[1] = static_cast<uint8_t>(data_len);
    std::memcpy(payload + 2, data, data_len);

    // Fill padding with random bytes (matches AEAD ciphertext entropy)
    if (padded > inner_len)
        randombytes_buf(payload + inner_len, padded - inner_len);

    return TlsRecordBuilder::write_record(
        out, TlsRecordBuilder::CONTENT_APP_DATA, payload, padded);
}

bool TlsProfile::unwrap(uint8_t* out, size_t* out_len,
                        const uint8_t* data, size_t data_len) {
    uint8_t content_type;
    const uint8_t* payload;
    size_t payload_len;

    size_t consumed = TlsRecordBuilder::parse_record(
        data, data_len, content_type, payload, payload_len);
    if (consumed == 0) return false;
    if (content_type != TlsRecordBuilder::CONTENT_APP_DATA) return false;
    if (payload_len < 2) return false;

    uint16_t actual_len = static_cast<uint16_t>((payload[0] << 8) | payload[1]);
    if (actual_len + 2 > payload_len) return false;

    std::memcpy(out, payload + 2, actual_len);
    *out_len = actual_len;
    return true;
}

// ---------------------------------------------------------------------------
// Handshake wrapping
// ---------------------------------------------------------------------------

size_t TlsProfile::wrap_handshake(uint8_t* out,
                                  const uint8_t* noise_msg, size_t msg_len,
                                  bool is_initiator) {
    if (is_initiator) {
        // Noise msg1 (96 bytes): e(32) + encrypted_s(48) + tag(16)
        const uint8_t* ephemeral = noise_msg;       // 32 bytes
        const uint8_t* enc_payload = noise_msg + 32; // 64 bytes

        return TlsRecordBuilder::build_client_hello(
            out, ephemeral, enc_payload, msg_len - 32);
    } else {
        // Noise msg2 (48 bytes): e(32) + tag(16)
        const uint8_t* ephemeral = noise_msg;

        size_t total = TlsRecordBuilder::build_server_hello(
            out, ephemeral, client_session_id_, client_session_id_len_);

        // Send the 16-byte payload tag as a fake encrypted handshake record
        if (msg_len > 32) {
            uint8_t fake_enc[64];
            size_t tag_len = msg_len - 32;
            std::memcpy(fake_enc, noise_msg + 32, tag_len);
            // Pad to look like a real encrypted handshake message
            size_t pad = 64 - tag_len;
            if (pad > 0) randombytes_buf(fake_enc + tag_len, pad);
            total += TlsRecordBuilder::write_record(
                out + total, TlsRecordBuilder::CONTENT_APP_DATA, fake_enc, 64);
        }

        return total;
    }
}

bool TlsProfile::unwrap_handshake(uint8_t* out, size_t* out_len,
                                  const uint8_t* data, size_t data_len,
                                  bool is_initiator) {
    // is_initiator = true means WE are the initiator, so we're RECEIVING ServerHello
    // is_initiator = false means WE are the responder, so we're RECEIVING ClientHello

    uint8_t content_type;
    const uint8_t* payload;
    size_t payload_len;

    // Parse first record (Handshake: ClientHello or ServerHello)
    size_t consumed = TlsRecordBuilder::parse_record(
        data, data_len, content_type, payload, payload_len);
    if (consumed == 0 || content_type != TlsRecordBuilder::CONTENT_HANDSHAKE)
        return false;

    if (!is_initiator) {
        // We're responder, receiving ClientHello → extract Noise msg1
        uint8_t ephemeral[32];
        uint8_t enc_payload[128];
        size_t enc_len = 0;

        if (!TlsRecordBuilder::parse_client_hello(
                payload, payload_len, ephemeral, enc_payload, &enc_len,
                client_session_id_, &client_session_id_len_))
            return false;

        // Reconstruct Noise msg1: e(32) + encrypted data
        std::memcpy(out, ephemeral, 32);
        std::memcpy(out + 32, enc_payload, enc_len);
        *out_len = 32 + enc_len;
        return true;
    } else {
        // We're initiator, receiving ServerHello → extract Noise msg2
        uint8_t ephemeral[32];
        if (!TlsRecordBuilder::parse_server_hello(payload, payload_len, ephemeral))
            return false;

        std::memcpy(out, ephemeral, 32);
        size_t pos = 32;

        // Skip CCS record
        size_t offset = consumed;
        if (offset < data_len) {
            size_t ccs = TlsRecordBuilder::parse_record(
                data + offset, data_len - offset, content_type, payload, payload_len);
            if (ccs > 0 && content_type == TlsRecordBuilder::CONTENT_CCS)
                offset += ccs;
        }

        // Read the encrypted record containing the payload tag
        if (offset < data_len) {
            size_t enc = TlsRecordBuilder::parse_record(
                data + offset, data_len - offset, content_type, payload, payload_len);
            if (enc > 0 && content_type == TlsRecordBuilder::CONTENT_APP_DATA
                && payload_len >= 16) {
                std::memcpy(out + pos, payload, 16); // payload tag
                pos += 16;
            }
        }

        *out_len = pos;
        return true;
    }
}
