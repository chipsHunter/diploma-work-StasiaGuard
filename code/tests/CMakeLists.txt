add_executable(vpn-test-crypto test_crypto.cpp)
target_link_libraries(vpn-test-crypto PRIVATE vpn-core)

add_executable(vpn-test-anti-replay test_anti_replay.cpp)
target_link_libraries(vpn-test-anti-replay PRIVATE vpn-core)

add_executable(vpn-test-tun test_tun.cpp)
target_link_libraries(vpn-test-tun PRIVATE vpn-core)
