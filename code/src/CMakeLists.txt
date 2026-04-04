add_library(vpn-core
    packet.cpp
    crypto_engine.cpp
    key_pair.cpp
    anti_replay.cpp
    tun_device.cpp
)

target_include_directories(vpn-core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(vpn-core PUBLIC PkgConfig::SODIUM ${YAMLCPP_TARGET})

add_executable(vpn main.cpp)
target_link_libraries(vpn PRIVATE vpn-core)
