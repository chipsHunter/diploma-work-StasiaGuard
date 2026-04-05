#pragma once

#include <cstddef>
#include <cstdint>

class TlsRecordBuilder {
public:
    static constexpr uint8_t CONTENT_HANDSHAKE = 0x16;
    static constexpr uint8_t CONTENT_CCS       = 0x14;
    static constexpr uint8_t CONTENT_APP_DATA  = 0x17;
    static constexpr size_t  RECORD_HEADER_LEN = 5;

    // Write a generic TLS record: [type][0x03 0x03][length][payload]
    static size_t write_record(uint8_t* out, uint8_t content_type,
                               const uint8_t* payload, size_t payload_len);

    // Build ClientHello with Noise msg1 data embedded:
    //   noise_ephemeral (32 bytes) → key_share extension
    //   noise_payload   (64 bytes) → session_ticket extension
    // Returns total bytes written (multiple records: Handshake + CCS).
    static size_t build_client_hello(uint8_t* out,
                                     const uint8_t* noise_ephemeral,
                                     const uint8_t* noise_payload,
                                     size_t noise_payload_len);

    // Build ServerHello with Noise msg2 data:
    //   noise_ephemeral (32 bytes) → key_share extension
    //   session_id echoed from client
    // Returns total bytes written (multiple records: Handshake + CCS).
    static size_t build_server_hello(uint8_t* out,
                                     const uint8_t* noise_ephemeral,
                                     const uint8_t* client_session_id,
                                     size_t session_id_len);

    // Build ChangeCipherSpec record (constant 6 bytes)
    static size_t build_ccs(uint8_t* out);

    // Parse a TLS record header from data.
    // Sets content_type, payload pointer, payload_len.
    // Returns total bytes consumed (header + payload), or 0 on error.
    static size_t parse_record(const uint8_t* data, size_t data_len,
                               uint8_t& content_type,
                               const uint8_t*& payload, size_t& payload_len);

    // Extract Noise data from a parsed ClientHello payload.
    static bool parse_client_hello(const uint8_t* record_payload,
                                   size_t record_len,
                                   uint8_t* noise_ephemeral,
                                   uint8_t* noise_payload,
                                   size_t* noise_payload_len,
                                   uint8_t* session_id_out,
                                   size_t* session_id_len);

    // Extract Noise data from a parsed ServerHello payload.
    static bool parse_server_hello(const uint8_t* record_payload,
                                   size_t record_len,
                                   uint8_t* noise_ephemeral);
};
