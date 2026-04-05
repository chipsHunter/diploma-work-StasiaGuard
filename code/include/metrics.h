#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

struct Metrics {
    // Business metrics
    std::atomic<uint64_t> active_peers{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> handshakes_total{0};
    std::atomic<uint64_t> handshakes_failed{0};

    // Technical metrics
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> decrypt_errors{0};
    std::atomic<uint64_t> replay_rejected{0};
    std::atomic<uint64_t> rekeys_total{0};
    std::atomic<uint64_t> padding_overhead_bytes{0};

    std::chrono::steady_clock::time_point started_at;

    Metrics() : started_at(std::chrono::steady_clock::now()) {}

    uint64_t uptime_seconds() const;
    std::string to_json() const;
};

// Global metrics instance
Metrics& global_metrics();
