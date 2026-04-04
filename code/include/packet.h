#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

class Packet {
public:
    static constexpr size_t MAX_SIZE = 1420;

    Packet() = default;

    uint8_t* data() { return buf_; }
    const uint8_t* data() const { return buf_; }

    size_t length() const { return length_; }
    void set_length(size_t len) { length_ = (len <= MAX_SIZE) ? len : MAX_SIZE; }

    uint32_t get_dest_ip() const;
    uint32_t get_src_ip() const;

private:
    uint8_t buf_[MAX_SIZE]{};
    size_t length_ = 0;
};
