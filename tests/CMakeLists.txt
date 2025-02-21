
# command-line arguments (for test programs)
add_subdirectory(CLI11)


add_library(tests_common STATIC utils.cpp)
target_link_libraries(tests_common PUBLIC
quic CLI11::CLI11 libquic_internal-warnings gnutls::gnutls)

macro(link_test_dep x)
    string(TOUPPER "${x}" BIG_X)
    if(TARGET ${x}::${x})
        target_link_libraries(tests_common INTERFACE ${x}::${x})
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(${BIG_X} ${x} REQUIRED IMPORTED_TARGET)
        target_link_libraries(tests_common INTERFACE PkgConfig::${BIG_X})
    endif()
endmacro()

# We need hogweed for generating Ed25519 keys (this is already a gnutls dependency, so we
# shouldn't be adding any new dep by requiring it)
link_test_dep(hogweed)
link_test_dep(nettle)

function(extra_linking target)
if(WIN32 AND NOT BUILD_SHARED_LIBS)
target_link_libraries(${target} PRIVATE -static)
endif()
endfunction()

if(LIBQUIC_BUILD_TESTS)
    add_subdirectory(Catch2)
    
    add_executable(alltests
        main.cpp
        
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
        012-watermarks.cpp
        013-eventhandler.cpp
        014-0rtt.cpp
        015-bt-encoding.cpp
        016-stateless_reset.cpp

        case_logger.cpp
    )

    target_link_libraries(alltests PRIVATE tests_common Catch2::Catch2)
    extra_linking(alltests)
    
endif()

if(LIBQUIC_BUILD_SPEEDTEST)
    set(LIBQUIC_SPEEDTEST_PREFIX "" CACHE STRING "Binary prefix for speedtest binaries")
    set(speedtests speedtest-client speedtest-server dgram-speed-client dgram-speed-server ping-server)
    if(NOT WIN32)
        # Currently doesn't build on windows because it relies on sigset_t to handle stopping it.
        set(speedtests ${speedtests} ping-client)
    endif()
    foreach(x ${speedtests})
        add_executable(${x} ${x}.cpp)
        target_link_libraries(${x} PRIVATE tests_common)
        set_target_properties(${x} PROPERTIES OUTPUT_NAME ${LIBQUIC_SPEEDTEST_PREFIX}${x})
        extra_linking(${x})
    endforeach()

    if(LIBQUIC_INSTALL)
        install(
            TARGETS ${speedtests}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
endif()
