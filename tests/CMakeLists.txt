add_executable(tcp_connect
    tcp_connect.cpp)
target_link_libraries(tcp_connect PUBLIC quic)

add_executable(tcp_listen
    tcp_listen.cpp)
target_link_libraries(tcp_listen PUBLIC quic)

