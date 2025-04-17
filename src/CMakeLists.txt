set(libquic_send_allowed "gso, sendmmsg, sendmsg")

configure_file(version.cpp.in version.cpp @ONLY)

add_library(quic
    address.cpp
    btstream.cpp
    connection.cpp
    connection_ids.cpp
    context.cpp
    datagram.cpp
    endpoint.cpp
    format.cpp
    gnutls_creds.cpp
    gnutls_crypto.cpp
    gnutls_session.cpp
    iochannel.cpp
    ip.cpp
    loop.cpp
    messages.cpp
    network.cpp
    result.cpp
    stream.cpp
    udp.cpp
    utils.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/version.cpp
)

target_link_libraries(quic
    PUBLIC
    ngtcp2::crypto
    gnutls::gnutls
    oxen::logging
    libquic_external
    oxenc
    PRIVATE
    libevent::core
    libevent::threads
    libquic_internal
    nettle::nettle
)

target_compile_features(quic INTERFACE cxx_std_20)

set_target_properties(quic PROPERTIES LIBRARY_OUTPUT_NAME oxenquic)
if(LIBQUIC_VERSION_SO)
    set_target_properties(quic PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
endif()

if(WIN32)
    target_link_libraries(quic PUBLIC ws2_32)
endif()

if(BUILD_STATIC_DEPS AND MINGW)
    set_source_files_properties(
        gnutls_creds.cpp gnutls_session.cpp
        PROPERTIES COMPILE_DEFINITIONS GNUTLS_INTERNAL_BUILD)
endif()

set(libquic_send_default "sendmsg")
set(libquic_recvmmsg_default OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(libquic_send_default "gso")
    set(libquic_recvmmsg_default ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(libquic_send_default "sendmmsg")
    set(libquic_recvmmsg_default ON)
endif()

set(LIBQUIC_SEND "${libquic_send_default}" CACHE STRING "Packet send implementation to use; one of: ${libquic_send_allowed}")
set(LIBQUIC_RECVMMSG ${libquic_recvmmsg_default} CACHE BOOL "Use recvmmsg when receiving UDP packets")

if(LIBQUIC_SEND STREQUAL "gso")
    message(STATUS "Building with sendmmsg+GSO packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_GSO)
elseif(LIBQUIC_SEND STREQUAL "sendmmsg")
    message(STATUS "Building with sendmmsg (without GSO) packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_SENDMMSG)
else()
    message(STATUS "Building without sendmmsg/GSO packet sending")
endif()

if(LIBQUIC_RECVMMSG)
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_RECVMMSG)
    message(STATUS "Building with recvmmsg support")
else()
    message(STATUS "Building without recvmmsg support")
endif()

if(LIBQUIC_INSTALL)
    install(
        TARGETS quic
        EXPORT oxenquicConfig
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
