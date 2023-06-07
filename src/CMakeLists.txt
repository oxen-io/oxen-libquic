
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
