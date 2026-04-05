#pragma once

#include <cstddef>
#include <cstdint>

class TrafficProfile {
public:
    virtual ~TrafficProfile() = default;

    // Wrap encrypted payload into transport format. Returns bytes written.
    virtual size_t wrap(uint8_t* out, const uint8_t* data, size_t data_len) = 0;

    // Unwrap transport data, extract encrypted payload.
    virtual bool unwrap(uint8_t* out, size_t* out_len,
                        const uint8_t* data, size_t data_len) = 0;

    // Wrap a Noise handshake message into TLS handshake records.
    // is_initiator: true = ClientHello, false = ServerHello
    virtual size_t wrap_handshake(uint8_t* out,
                                  const uint8_t* noise_msg, size_t msg_len,
                                  bool is_initiator) = 0;

    // Unwrap TLS handshake records, extract Noise message.
    virtual bool unwrap_handshake(uint8_t* out, size_t* out_len,
                                  const uint8_t* data, size_t data_len,
                                  bool is_initiator) = 0;
};
