#include "anti_replay.h"

AntiReplay::AntiReplay() : bitmap_(0), last_nonce_(0) {}

bool AntiReplay::check_and_update(uint64_t nonce) {
    if (nonce > last_nonce_) {
        uint64_t diff = nonce - last_nonce_;
        bitmap_ = (diff >= WINDOW_SIZE) ? 1 : (bitmap_ << diff) | 1;
        last_nonce_ = nonce;
        return true;
    }

    uint64_t diff = last_nonce_ - nonce;
    if (diff >= WINDOW_SIZE) return false;

    uint64_t mask = uint64_t(1) << diff;
    if (bitmap_ & mask) return false;

    bitmap_ |= mask;
    return true;
}

void AntiReplay::reset() {
    bitmap_ = 0;
    last_nonce_ = 0;
}
