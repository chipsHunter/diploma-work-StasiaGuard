#include "tls_profile.h"
#include "noise_handshake.h"
#include "padding_calculator.h"
#include "tls_record_builder.h"

#include <cstring>
#include <sodium.h>

TlsProfile::TlsProfile()
    : client_session_id_len_(0)
    , need_client_finished_(false) {
    std::memset(client_session_id_, 0, sizeof(client_session_id_));
}

// ---------------------------------------------------------------------------
// Fake encrypted handshake records for realistic TLS 1.3 mimicry
// ---------------------------------------------------------------------------

// After ServerHello + CCS, a real TLS 1.3 server sends encrypted:
//   EncryptedExtensions (~200 bytes)
//   Certificate         (~1500-2500 bytes, depends on chain)
//   CertificateVerify   (~150 bytes)
//   Finished            (~50 bytes)
// All wrapped in application_data (0x17) records.
// We generate random records of matching sizes, embedding the Noise
// payload tag in the first record.
size_t TlsProfile::write_fake_server_handshake(uint8_t* out,
                                               const uint8_t* noise_tag,
                                               size_t tag_len) {
    size_t total = 0;

    // Record 1: "EncryptedExtensions" (~200 bytes, contains Noise tag)
    {
        uint8_t buf[256];
        size_t real = (tag_len > 0) ? tag_len : 0;
        std::memcpy(buf, noise_tag, real);
        randombytes_buf(buf + real, 200 - real);
        total += TlsRecordBuilder::write_record(
            out + total, TlsRecordBuilder::CONTENT_APP_DATA, buf, 200);
    }

    // Record 2: "Certificate" (~1800 bytes)
    {
        uint8_t buf[2048];
        randombytes_buf(buf, 1800);
        total += TlsRecordBuilder::write_record(
            out + total, TlsRecordBuilder::CONTENT_APP_DATA, buf, 1800);
    }

    // Record 3: "CertificateVerify" (~150 bytes)
    {
        uint8_t buf[256];
        randombytes_buf(buf, 150);
        total += TlsRecordBuilder::write_record(
            out + total, TlsRecordBuilder::CONTENT_APP_DATA, buf, 150);
    }

    // Record 4: "Finished" (~52 bytes)
    {
        uint8_t buf[64];
        randombytes_buf(buf, 52);
        total += TlsRecordBuilder::write_record(
            out + total, TlsRecordBuilder::CONTENT_APP_DATA, buf, 52);
    }

    return total;
}

// Client sends CCS + encrypted Finished before first data
size_t TlsProfile::write_fake_client_finished(uint8_t* out) {
    size_t total = 0;

    // CCS
    total += TlsRecordBuilder::build_ccs(out + total);

    // Encrypted Finished (~64 bytes)
    uint8_t buf[64];
    randombytes_buf(buf, 64);
    total += TlsRecordBuilder::write_record(
        out + total, TlsRecordBuilder::CONTENT_APP_DATA, buf, 64);

    return total;
}

// ---------------------------------------------------------------------------
// Data wrapping: payload → TLS application_data record with padding
//
// Wire format inside the TLS record:
//   [2 bytes: actual data length (big-endian)][data][random padding]
// ---------------------------------------------------------------------------

size_t TlsProfile::wrap(uint8_t* out,
                        const uint8_t* data, size_t data_len) {
    size_t total = 0;

    // First data packet from client: prepend CCS + Finished
    if (need_client_finished_) {
        total += write_fake_client_finished(out);
        need_client_finished_ = false;
    }

    size_t inner_len = 2 + data_len;
    size_t padded = PaddingCalculator::calculate(inner_len);

    uint8_t payload[8192];
    payload[0] = static_cast<uint8_t>(data_len >> 8);
    payload[1] = static_cast<uint8_t>(data_len);
    std::memcpy(payload + 2, data, data_len);

    if (padded > inner_len)
        randombytes_buf(payload + inner_len, padded - inner_len);

    total += TlsRecordBuilder::write_record(
        out + total, TlsRecordBuilder::CONTENT_APP_DATA, payload, padded);
    return total;
}

bool TlsProfile::unwrap(uint8_t* out, size_t* out_len,
                        const uint8_t* data, size_t data_len) {
    size_t offset = 0;

    // Skip CCS records and non-data records at the beginning
    // (client Finished arrives prepended to first data)
    while (offset < data_len) {
        if (data_len - offset < TlsRecordBuilder::RECORD_HEADER_LEN) return false;

        uint8_t ct = data[offset];
        uint16_t rec_len = static_cast<uint16_t>(
            (data[offset + 3] << 8) | data[offset + 4]);

        if (ct == TlsRecordBuilder::CONTENT_APP_DATA) {
            // Check if this is a real data record (has our 2-byte length prefix)
            const uint8_t* payload = data + offset + TlsRecordBuilder::RECORD_HEADER_LEN;
            uint16_t actual_len = static_cast<uint16_t>((payload[0] << 8) | payload[1]);

            if (actual_len + 2 <= rec_len && actual_len <= 4096) {
                // This looks like our data record
                std::memcpy(out, payload + 2, actual_len);
                *out_len = actual_len;
                return true;
            }
        }

        // Skip this record (CCS or fake handshake)
        offset += TlsRecordBuilder::RECORD_HEADER_LEN + rec_len;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Handshake wrapping
// ---------------------------------------------------------------------------

size_t TlsProfile::wrap_handshake(uint8_t* out,
                                  const uint8_t* noise_msg, size_t msg_len,
                                  bool is_initiator) {
    if (is_initiator) {
        // Noise msg1 (96 bytes): e(32) + encrypted_s(48) + tag(16)
        const uint8_t* ephemeral = noise_msg;
        const uint8_t* enc_payload = noise_msg + 32;

        size_t total = TlsRecordBuilder::build_client_hello(
            out, ephemeral, enc_payload, msg_len - 32);

        // Mark: next wrap() call should prepend CCS + Finished
        need_client_finished_ = true;

        return total;
    } else {
        // Noise msg2 (48 bytes): e(32) + tag(16)
        const uint8_t* ephemeral = noise_msg;

        size_t total = TlsRecordBuilder::build_server_hello(
            out, ephemeral, client_session_id_, client_session_id_len_);

        // Append realistic fake encrypted handshake records
        const uint8_t* noise_tag = (msg_len > 32) ? noise_msg + 32 : nullptr;
        size_t tag_len = (msg_len > 32) ? msg_len - 32 : 0;
        total += write_fake_server_handshake(out + total, noise_tag, tag_len);

        return total;
    }
}

bool TlsProfile::unwrap_handshake(uint8_t* out, size_t* out_len,
                                  const uint8_t* data, size_t data_len,
                                  bool is_initiator) {
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

        // Skip CCS, then read first 0x17 record for Noise tag (16 bytes)
        size_t offset = consumed;
        while (offset < data_len) {
            size_t rec = TlsRecordBuilder::parse_record(
                data + offset, data_len - offset, content_type, payload, payload_len);
            if (rec == 0) break;
            offset += rec;

            if (content_type == TlsRecordBuilder::CONTENT_CCS)
                continue;

            if (content_type == TlsRecordBuilder::CONTENT_APP_DATA && payload_len >= 16) {
                // First encrypted record contains Noise tag in first 16 bytes
                std::memcpy(out + pos, payload, 16);
                pos += 16;
                break; // remaining records are fake, skip them
            }
        }

        *out_len = pos;
        return true;
    }
}
