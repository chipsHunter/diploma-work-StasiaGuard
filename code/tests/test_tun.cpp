#include "tun_device.h"
#include "packet.h"

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    std::cout << "TunDevice test (requires sudo):\n";

    TunDevice tun;

    if (!tun.open("tun-test")) {
        std::cerr << "Failed to open TUN device. Run with: sudo ./build/vpn-test-tun\n";
        return 1;
    }
    std::cout << "  opened: " << tun.name() << " (fd=" << tun.fd() << ")\n";

    tun.configure("10.200.200.1", 24);
    std::cout << "  configured 10.200.200.1/24\n";

    pid_t pid = fork();
    if (pid == 0) {
        execlp("ping", "ping", "-c", "1", "-W", "2", "10.200.200.2", nullptr);
        _exit(1);
    }

    Packet pkt;
    std::cout << "  waiting for packet...\n";

    if (tun.read_packet(pkt)) {
        struct in_addr src, dst;
        src.s_addr = pkt.get_src_ip();
        dst.s_addr = pkt.get_dest_ip();
        std::cout << "  received: " << pkt.length() << " bytes, "
                  << inet_ntoa(src) << " -> " << inet_ntoa(dst) << "\n";
    } else {
        std::cerr << "  failed to read packet\n";
        waitpid(pid, nullptr, 0);
        return 1;
    }

    tun.close();
    std::cout << "  device closed\n";

    waitpid(pid, nullptr, 0);
    std::cout << "TunDevice test passed.\n";
    return 0;
}
