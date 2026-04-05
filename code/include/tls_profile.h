#pragma once

#include "traffic_profile.h"

#include <cstdint>

class TlsProfile : public TrafficProfile {
public:
    TlsProfile();

    size_t wrap(uint8_t* out, const uint8_t* data, size_t data_len) override;
    bool unwrap(uint8_t* out, size_t* out_len,
                const uint8_t* data, size_t data_len) override;

    size_t wrap_handshake(uint8_t* out,
                          const uint8_t* noise_msg, size_t msg_len,
                          bool is_initiator) override;

    bool unwrap_handshake(uint8_t* out, size_t* out_len,
                          const uint8_t* data, size_t data_len,
                          bool is_initiator) override;

private:
    uint8_t client_session_id_[32];
    size_t  client_session_id_len_;
};
