#include "anti_replay.h"

#include <cassert>
#include <iostream>

int main() {
    AntiReplay ar;
    std::cout << "AntiReplay tests:\n";

    // Accept sequential nonces
    assert(ar.check_and_update(1));
    assert(ar.check_and_update(2));
    assert(ar.check_and_update(3));
    std::cout << "  accept 1, 2, 3: PASS\n";

    // Reject replay
    assert(!ar.check_and_update(2));
    std::cout << "  reject replay 2: PASS\n";

    // Accept large jump
    assert(ar.check_and_update(100));
    std::cout << "  accept 100: PASS\n";

    // Reject nonce outside window (100 - 30 = 70 > 64)
    assert(!ar.check_and_update(30));
    std::cout << "  reject 30 (outside window): PASS\n";

    // Accept nonce within window
    assert(ar.check_and_update(50));
    std::cout << "  accept 50 (within window): PASS\n";

    // Reject replay of 50
    assert(!ar.check_and_update(50));
    std::cout << "  reject replay 50: PASS\n";

    // Reset and accept 0
    ar.reset();
    assert(ar.check_and_update(0));
    assert(!ar.check_and_update(0));
    std::cout << "  reset + accept/reject 0: PASS\n";

    std::cout << "All anti-replay tests passed.\n";
    return 0;
}
