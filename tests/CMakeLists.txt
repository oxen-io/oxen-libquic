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
    
    main.cpp
)
target_link_libraries(alltests PUBLIC quic Catch2::Catch2 CLI11::CLI11)

#add_executable(
#    test_client
#    test_client.cpp)
#target_link_libraries(test_client PRIVATE quic)

#add_executable(
#    test_server
#    test_server.cpp)
#target_link_libraries(test_server PRIVATE quic)

#add_executable(
#    test_multiclient
#    test_multiclient.cpp)
#target_link_libraries(test_multiclient PUBLIC quic)

foreach(x speedtest-client speedtest-server)
    add_executable(${x} ${x}.cpp)
    target_link_libraries(${x} PRIVATE quic CLI11::CLI11)
endforeach()
