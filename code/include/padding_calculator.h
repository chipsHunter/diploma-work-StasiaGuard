#pragma once

#include <cstddef>

class PaddingCalculator {
public:
    // Returns the target padded size for a given payload.
    // Produces a bimodal distribution: small (64-256) and large (512-4096).
    static size_t calculate(size_t payload_len);
};
