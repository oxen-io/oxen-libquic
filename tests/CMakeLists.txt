add_subdirectory(Catch2)

# command-line arguments (for test programs)
add_subdirectory(CLI11)

add_executable(test_all
    001-handshake.cpp
#    002-send-receive.cpp
#    003-multiclient.cpp
#    004-streams.cpp
#    005-chunked-sender.cpp
#    006-server-send.cpp
#    007-server-streams.cpp
)
target_link_libraries(test_all PUBLIC quic Catch2::Catch2WithMain)
set_target_properties(test_all PROPERTIES OUTPUT_NAME alltests)

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

#if(NOT TARGET sodium)
#    find_package(PkgConfig REQUIRED)
#    pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18 IMPORTED_TARGET)
#    add_library(sodium INTERFACE)
#    target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
#endif()

#foreach(x speedtest-client speedtest-server)
#    add_executable(${x} ${x}.cpp)
#    target_link_libraries(${x} PRIVATE quic CLI11::CLI11 sodium)
#endforeach()
