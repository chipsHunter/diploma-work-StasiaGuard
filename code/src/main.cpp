#include <cstring>
#include <iostream>
#include <sodium.h>

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "\n"
              << "Options:\n"
              << "  --config <path>   Path to YAML configuration file\n"
              << "  --help            Show this help message\n"
              << "  --version         Show version information\n";
}

static void print_version() {
    std::cout << "vpn 0.1.0\n"
              << "libsodium " << sodium_version_string() << "\n";
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (std::strcmp(argv[i], "--version") == 0 || std::strcmp(argv[i], "-v") == 0) {
            print_version();
            return 0;
        }
    }

    if (sodium_init() < 0) {
        std::cerr << "error: failed to initialize libsodium\n";
        return 1;
    }

    print_usage(argv[0]);
    return 0;
}
