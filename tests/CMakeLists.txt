add_subdirectory(Catch2)

# command-line arguments (for test programs)
add_subdirectory(CLI11)

add_executable(alltests
    001-handshake.cpp
    002-send-receive.cpp
    003-multiclient.cpp
    004-streams.cpp
    005-chunked-sender.cpp
    006-server-send.cpp
    007-datagrams.cpp
    008-ed-keys.cpp
    009-close.cpp
    
    main.cpp
)
target_link_libraries(alltests
    PUBLIC quic Catch2::Catch2 CLI11::CLI11
    PRIVATE internal-warnings
)

foreach(x speedtest-client speedtest-server dgram-speed-client dgram-speed-server)
    add_executable(${x} ${x}.cpp)
    target_link_libraries(${x} PRIVATE quic CLI11::CLI11)
endforeach()
