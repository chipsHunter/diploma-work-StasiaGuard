#include "packet.h"

uint32_t Packet::get_dest_ip() const {
    if (length_ < 20) return 0;
    uint32_t ip;
    std::memcpy(&ip, buf_ + 16, 4);
    return ip;
}

uint32_t Packet::get_src_ip() const {
    if (length_ < 20) return 0;
    uint32_t ip;
    std::memcpy(&ip, buf_ + 12, 4);
    return ip;
}
