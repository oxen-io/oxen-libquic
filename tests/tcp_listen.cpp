#include "quic.hpp"

#include <iostream>
#include <chrono>
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

    auto shared_ctx = std::shared_ptr<oxen::quic::Context>{};
    const auto port = 10000;

    shared_ctx->server_call(port);
    
 
    return 0;
}
