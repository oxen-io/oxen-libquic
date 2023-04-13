add_library(headers INTERFACE)

target_include_directories(headers INTERFACE ../include/quic)

if(WARNINGS_AS_ERRORS)
    target_compile_options(headers INTERFACE -Werror)
endif()

add_library(libquic
    STATIC
    client.cpp
    connection.cpp
    server.cpp
    stream.cpp
    tunnel.cpp
)

target_link_libraries(libquic
    headers    
)
