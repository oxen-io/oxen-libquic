
# command-line arguments (for test programs)
add_subdirectory(CLI11)

add_library(tests_common STATIC utils.cpp)
target_link_libraries(tests_common PUBLIC
    quic CLI11::CLI11 libquic_internal-warnings gnutls::gnutls)

# We need hogweed for generating Ed25519 keys (this is already a gnutls dependency, so we shouldn't
# be adding any new dep by requiring it)
if(TARGET hogweed::hogweed)
    target_link_libraries(tests_common INTERFACE hogweed::hogweed)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(HOGWEED hogweed REQUIRED IMPORTED_TARGET)
    target_link_libraries(tests_common INTERFACE PkgConfig::HOGWEED)
endif()

function(extra_linking target)
    if(WIN32 AND NOT BUILD_SHARED_LIBS)
        target_link_libraries(${target} PRIVATE -static)
    endif()
endfunction()


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
        011-manual_transmission.cpp

        main.cpp
        case_logger.cpp
    )
    target_link_libraries(alltests PRIVATE tests_common Catch2::Catch2)
    extra_linking(alltests)

endif()

if(LIBQUIC_BUILD_SPEEDTEST)
    add_library(speedtest_common STATIC speedtest-server.cpp)
    target_link_libraries(speedtest_common PUBLIC tests_common)

    set(LIBQUIC_SPEEDTEST_PREFIX "" CACHE STRING "Binary prefix for speedtest binaries")
    set(speedtests speedtest speedtest-client dgram-speed-client)
    foreach(x ${speedtests})
        add_executable(${x} ${x}.cpp)
        target_link_libraries(${x} PRIVATE speedtest_common)
        set_target_properties(${x} PROPERTIES OUTPUT_NAME ${LIBQUIC_SPEEDTEST_PREFIX}${x})
        extra_linking(${x})
    endforeach()

    # FIXME: temporarily add `-server` suffix until speedtest.cpp becomes a dual server/client
    set_target_properties(speedtest PROPERTIES OUTPUT_NAME ${LIBQUIC_SPEEDTEST_PREFIX}speedtest-server)

    if(LIBQUIC_INSTALL)
        install(
            TARGETS ${speedtests}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
endif()
