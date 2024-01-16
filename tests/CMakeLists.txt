
# command-line arguments (for test programs)
add_subdirectory(CLI11)

add_library(tests_common STATIC utils.cpp)
target_link_libraries(tests_common PUBLIC
    quic CLI11::CLI11 libquic_internal-warnings gnutls::gnutls)

# We need hogweed for generating Ed25519 keys (this is already a gnutls dependency, so we shouldn't
# be adding any new dep by requiring it)
if(TARGET hogweed)
    target_link_libraries(tests_common INTERFACE hogweed)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(HOGWEED hogweed REQUIRED IMPORTED_TARGET)
    target_link_libraries(tests_common INTERFACE PkgConfig::HOGWEED)
endif()

if(LIBQUIC_BUILD_TESTS)
    add_subdirectory(Catch2)

    add_executable(alltests
        001-handshake.cpp
        002-send-receive.cpp
        003-multiclient.cpp
        004-streams.cpp
        005-chunked-sender.cpp
        006-server-send.cpp
        007-datagrams.cpp
        008-conn_hooks.cpp
        009-alpns.cpp
        010-migration.cpp

        main.cpp
    )
    target_link_libraries(alltests PRIVATE tests_common Catch2::Catch2)

endif()

if(LIBQUIC_BUILD_SPEEDTEST)
    foreach(x speedtest-client speedtest-server dgram-speed-client dgram-speed-server)
        add_executable(${x} ${x}.cpp)
        target_link_libraries(${x} PRIVATE tests_common)
    endforeach()

endif()
