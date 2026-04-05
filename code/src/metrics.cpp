#include "metrics.h"

#include <sstream>

uint64_t Metrics::uptime_seconds() const {
    auto elapsed = std::chrono::steady_clock::now() - started_at;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
}

std::string Metrics::to_json() const {
    std::ostringstream ss;
    ss << "{"
       << "\"active_peers\":" << active_peers.load()
       << ",\"bytes_sent\":" << bytes_sent.load()
       << ",\"bytes_received\":" << bytes_received.load()
       << ",\"packets_sent\":" << packets_sent.load()
       << ",\"packets_received\":" << packets_received.load()
       << ",\"handshakes_total\":" << handshakes_total.load()
       << ",\"handshakes_failed\":" << handshakes_failed.load()
       << ",\"decrypt_errors\":" << decrypt_errors.load()
       << ",\"replay_rejected\":" << replay_rejected.load()
       << ",\"rekeys_total\":" << rekeys_total.load()
       << ",\"padding_overhead_bytes\":" << padding_overhead_bytes.load()
       << ",\"uptime_seconds\":" << uptime_seconds()
       << "}";
    return ss.str();
}

static Metrics g_metrics;

Metrics& global_metrics() {
    return g_metrics;
}
