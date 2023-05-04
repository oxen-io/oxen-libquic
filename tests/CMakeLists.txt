add_subdirectory(Catch2)

# example integration of Catch2 using provided main
add_executable(
    001
    001-dtls_send_simple.cpp)
target_link_libraries(001 PUBLIC quic Catch2::Catch2WithMain)

# example integration of Catch2 using custom main
#add_executable(
#    foo-main
#    foo.cpp
#    foo-main.cpp)
#target_link_libraries(foo-main PRIVATE Catch2::Catch2)

