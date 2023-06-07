add_subdirectory(Catch2)

add_executable(test_all
    001-handshake.cpp
    002-send-receive.cpp
    003-multiclient.cpp
    004-stream-pending.cpp
    005-chunked-sender.cpp
)
target_link_libraries(test_all PUBLIC quic Catch2::Catch2WithMain)
set_target_properties(test_all PROPERTIES OUTPUT_NAME alltests)

add_executable(
    test_client
    test_client.cpp)
target_link_libraries(test_client PUBLIC quic)

add_executable(
    test_server
    test_server.cpp)
target_link_libraries(test_server PUBLIC quic)

add_executable(
    test_multiclient
    test_multiclient.cpp)
target_link_libraries(test_multiclient PUBLIC quic)
