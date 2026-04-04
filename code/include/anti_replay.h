#pragma once

#include <cstdint>

class AntiReplay {
public:
    AntiReplay();

    bool check_and_update(uint64_t nonce);
    void reset();

private:
    static constexpr uint64_t WINDOW_SIZE = 64;
    uint64_t bitmap_;
    uint64_t last_nonce_;
};
