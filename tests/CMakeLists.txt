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
    test_client
    test_client.cpp)
target_link_libraries(test_client PUBLIC quic)

add_executable(
    test_server
    test_server.cpp)
target_link_libraries(test_server PUBLIC quic)

# example integration of Catch2 using custom main
#add_executable(
#    foo-main
#    foo.cpp
#    foo-main.cpp)
#target_link_libraries(foo-main PRIVATE Catch2::Catch2)

