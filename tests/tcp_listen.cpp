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
    std::string host{"127.0.01"};
    uint16_t port = 12345;

    shared_ctx->listen_to(host, port);

    size_t counter = 0;

    do {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});

        if (++counter % 30 == 0)
            std::cout << "Listening..." << std::endl;
    } while (run);
    
    return 0;
}
