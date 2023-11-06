add_library(quic
    address.cpp
    btstream.cpp
    connection.cpp
    context.cpp
    datagram.cpp
    endpoint.cpp
    format.cpp
    gnutls_crypto.cpp
    messages.cpp
    network.cpp
    stream.cpp
    udp.cpp
    utils.cpp
)

target_link_libraries(quic
    PUBLIC
    ngtcp2::crypto
    libevent::core libevent::threads
    gnutls::gnutls
    oxen::logging
    common
    oxenc
    PRIVATE
    internal
)

if(WIN32)
    target_link_libraries(quic PUBLIC ws2_32)
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
set(libquic_send_allowed "gso, sendmmsg, sendmsg")

set(LIBQUIC_SEND "${libquic_send_default}" CACHE STRING "Packet send implementation to use; one of: ${libquic_send_allowed}")

if(LIBQUIC_SEND STREQUAL "gso")
    message(STATUS "Building with sendmmsg+GSO packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_GSO)
elseif(LIBQUIC_SEND STREQUAL "sendmmsg")
    message(STATUS "Building with sendmmsg (without GSO) packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_SENDMMSG)
else()
    message(STATUS "Building without sendmmsg/GSO packet sending")
endif()

option(LIBQUIC_RECVMMSG "Use recvmmsg when receiving UDP packets" ${libquic_recvmmsg_default})
if(LIBQUIC_RECVMMSG)
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_RECVMMSG)
    message(STATUS "Building with recvmmsg support")
else()
    message(STATUS "Building without recvmmsg support")
endif()
