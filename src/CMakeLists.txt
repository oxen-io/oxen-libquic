
# Interface target for any general includes, flags, etc. that is meant to be inherited publicly.
add_library(common INTERFACE)
# Interface target for internal flags, include paths, etc. that are PRIVATE for project source
# compilation, but not for potential external targets that depend on us.
add_library(internal INTERFACE)

target_include_directories(common INTERFACE ../include)
target_include_directories(internal INTERFACE ../include/quic)

if(WARNINGS_AS_ERRORS)
    target_compile_options(internal INTERFACE -Werror)
endif()

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
    uvw::uvw-static
    oxen::logging
    common
    PRIVATE
    internal
)
