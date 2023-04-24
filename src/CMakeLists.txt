add_library(common INTERFACE)

target_include_directories(common INTERFACE ../include/quic)

if(WARNINGS_AS_ERRORS)
    target_compile_options(common INTERFACE -Werror)
endif()

add_library(quic
    client.cpp
    connection.cpp
    context.cpp
    crypto.cpp
    endpoint.cpp
    handler.cpp
    network.cpp
    server.cpp
    stream.cpp
    utils.cpp
)

target_link_libraries(quic
    PUBLIC
    ngtcp2::crypto
    gnutls
    uvw::uvw-static
    common
)

