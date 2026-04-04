#pragma once

#include "packet.h"
#include <string>

class TunDevice {
public:
    static constexpr int DEFAULT_MTU = 1420;

    TunDevice();
    ~TunDevice();

    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    bool open(const std::string& dev_name = "tun0");
    void configure(const std::string& ip, int prefix_len, int mtu = DEFAULT_MTU);

    bool read_packet(Packet& pkt);
    bool write_packet(const Packet& pkt);

    void close();

    int fd() const { return fd_; }
    const std::string& name() const { return name_; }

private:
    int fd_;
    std::string name_;
};
