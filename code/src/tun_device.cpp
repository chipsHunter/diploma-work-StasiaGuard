#include "tun_device.h"

#include <cstring>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

TunDevice::TunDevice() : fd_(-1) {}

TunDevice::~TunDevice() {
    close();
}

bool TunDevice::open(const std::string& dev_name) {
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        std::cerr << "error: cannot open /dev/net/tun\n";
        return false;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        std::cerr << "error: ioctl TUNSETIFF failed\n";
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    name_ = ifr.ifr_name;
    return true;
}

void TunDevice::configure(const std::string& ip, int prefix_len, int mtu) {
    std::string cmd;

    cmd = "ip addr add " + ip + "/" + std::to_string(prefix_len) + " dev " + name_;
    system(cmd.c_str());

    cmd = "ip link set dev " + name_ + " mtu " + std::to_string(mtu) + " up";
    system(cmd.c_str());
}

bool TunDevice::read_packet(Packet& pkt) {
    ssize_t n = ::read(fd_, pkt.data(), Packet::MAX_SIZE);
    if (n <= 0) return false;
    pkt.set_length(static_cast<size_t>(n));
    return true;
}

bool TunDevice::write_packet(const Packet& pkt) {
    ssize_t n = ::write(fd_, pkt.data(), pkt.length());
    return n == static_cast<ssize_t>(pkt.length());
}

void TunDevice::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}
