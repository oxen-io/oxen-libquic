#include "quic.hpp"

#include <iostream>
#include <csignal>
#include <chrono>
#include <memory>
#include <thread>


bool run{true};

void
signal_handler(int)
{
    run = false;
    int a;
}

int main(void)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto shared_ctx = std::make_shared<oxen::quic::Context>();
    auto local_addr = oxen::quic::Address{"127.0.0.1", uint16_t{4400}};
    std::string remote_host{"127.0.0.1"};
    uint16_t remote_port{12345};
    
    if (REMOTE_HOST)
        remote_host = REMOTE_HOST;
    if (REMOTE_PORT)
        remote_port = REMOTE_PORT;
    
    shared_ctx->client_call(local_addr, remote_host, remote_port);

    do {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    } while (run);
    
    
    return 0;
}
