add_subdirectory(Catch2)

add_executable(
    001
    001-handshake.cpp)
target_link_libraries(001 PUBLIC quic Catch2::Catch2WithMain)

add_executable(
    002
    002-send-receive.cpp)
target_link_libraries(002 PUBLIC quic Catch2::Catch2WithMain)

add_executable(
    003
    003-multiclient.cpp)
target_link_libraries(003 PUBLIC quic Catch2::Catch2WithMain)

add_executable(
    004
    004-stream-pending.cpp)
target_link_libraries(004 PUBLIC quic Catch2::Catch2WithMain)

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
