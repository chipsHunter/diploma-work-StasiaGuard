add_executable(vpn main.cpp)

target_include_directories(vpn PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(vpn PRIVATE PkgConfig::SODIUM ${YAMLCPP_TARGET})
