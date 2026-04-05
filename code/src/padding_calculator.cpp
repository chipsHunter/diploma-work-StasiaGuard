#include "padding_calculator.h"

#include <sodium.h>

// Bimodal target sizes mimicking HTTPS traffic distribution:
// ~60% small (64, 128, 192, 256) — HTTP/2 control frames
// ~40% large (512, 1024, 2048, 4096) — page data
static const size_t kSmallTargets[] = {64, 128, 192, 256};
static const size_t kLargeTargets[] = {512, 1024, 2048, 4096};

size_t PaddingCalculator::calculate(size_t payload_len) {
    if (payload_len == 0) return 64;

    // Already at a target size — no padding needed
    if (payload_len <= 256) {
        // Snap up to nearest small target
        for (size_t t : kSmallTargets) {
            if (payload_len <= t) return t;
        }
    }

    // Snap up to nearest large target
    for (size_t t : kLargeTargets) {
        if (payload_len <= t) return t;
    }

    // Payload exceeds largest target — round up to next 512-byte boundary
    return ((payload_len + 511) / 512) * 512;
}
