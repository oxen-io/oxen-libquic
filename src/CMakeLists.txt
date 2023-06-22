
add_library(quic
    client.cpp
    connection.cpp
    context.cpp
    crypto.cpp
    endpoint.cpp
    handler.cpp
    network.cpp
    opt.cpp
    server.cpp
    stream.cpp
    utils.cpp
)

target_link_libraries(quic
    PUBLIC
    ngtcp2::crypto
    gnutls
    uvw
    oxen::logging
    common
    PRIVATE
    internal
)

set(libquic_send_default "libuv_queue")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(libquic_send_default "gso")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(libquic_send_default "sendmmsg")
endif()
set(libquic_send_allowed "gso, sendmmsg, libuv_try, libuv_queue")

set(LIBQUIC_SEND "${libquic_send_default}" CACHE STRING "Packet send implementation to use; one of: ${libquic_send_allowed}")


if(LIBQUIC_SEND STREQUAL "gso")
    message(STATUS "Building with sendmmsg+GSO packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_GSO)
elseif(LIBQUIC_SEND STREQUAL "sendmmsg")
    message(STATUS "Building with sendmmsg (no GSO) packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_SENDMMSG)
elseif(LIBQUIC_SEND STREQUAL "libuv_queue")
    message(STATUS "Building with libuv queuing packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_LIBUV_QUEUING)
elseif(LIBQUIC_SEND STREQUAL "libuv_try")
    message(STATUS "Building with libuv try_send packet sender")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_LIBUV_TRY)
else()
    message(FATAL_ERROR "Unknown -DLIBQUIC_SEND value: '${LIBQUIC_SEND}'; supported values: ${libquic_send_allowed}")
endif()


option(LIBQUIC_RECVMMSG "Enables recvmmsg() use when receiving UDP packets, if supported on this system" ON)
if(NOT LIBQUIC_RECVMMSG)
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_LIBUV_NO_RECVMMSG)
    message(STATUS "Building without recvmmsg support")
else()
    message(STATUS "Building with recvmmsg, if available on this platform")
endif()
