#include "config.h"
#include "crypto_engine.h"
#include "key_pair.h"
#include "vpn_daemon.h"

#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sodium.h>

static VpnDaemon* g_daemon = nullptr;

static void signal_handler(int) {
    if (g_daemon) g_daemon->stop();
}

static void print_usage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " --config <path>   Run VPN daemon\n"
              << "  " << prog << " genkey             Generate private key\n"
              << "  " << prog << " pubkey             Derive public key from stdin\n"
              << "  " << prog << " --help             Show this message\n"
              << "  " << prog << " --version          Show version\n";
}

static int cmd_genkey() {
    if (sodium_init() < 0) return 1;
    KeyPair kp = KeyPair::generate();
    std::cout << Config::base64_encode(kp.private_key(), 32) << "\n";
    return 0;
}

static int cmd_pubkey() {
    if (sodium_init() < 0) return 1;
    std::string line;
    if (!std::getline(std::cin, line) || line.empty()) {
        std::cerr << "error: no key on stdin\n";
        return 1;
    }
    uint8_t priv[32];
    if (!Config::base64_decode(line, priv, 32)) {
        std::cerr << "error: invalid base64 key\n";
        return 1;
    }
    uint8_t pub[32];
    crypto_scalarmult_base(pub, priv);
    std::cout << Config::base64_encode(pub, 32) << "\n";
    sodium_memzero(priv, 32);
    return 0;
}

static int cmd_run(const char* config_path) {
    Config config;
    if (!config.load(config_path)) return 1;

    VpnDaemon daemon;
    g_daemon = &daemon;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    if (!daemon.start(config)) return 1;
    daemon.wait();

    g_daemon = nullptr;
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }

    std::string arg = argv[1];

    if (arg == "genkey")   return cmd_genkey();
    if (arg == "pubkey")   return cmd_pubkey();
    if (arg == "--help"  || arg == "-h") { print_usage(argv[0]); return 0; }
    if (arg == "--version" || arg == "-v") {
        std::cout << "vpn 0.1.0\nlibsodium "
                  << sodium_version_string() << "\n";
        return 0;
    }
    if (arg == "--config" || arg == "-c") {
        if (argc < 3) {
            std::cerr << "error: --config requires a path\n";
            return 1;
        }
        return cmd_run(argv[2]);
    }

    std::cerr << "error: unknown command '" << arg << "'\n";
    print_usage(argv[0]);
    return 1;
}
