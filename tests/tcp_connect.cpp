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

    auto ctx = std::make_shared<oxen::quic::Context>();
    std::string remote_host{"127.0.0.1"}, local_host{"127.0.0.1"};
    uint16_t remote_port{12345}, local_port{4400};
    std::string message;

    ctx->connect_to(local_host, local_port, remote_host, remote_port);
    
    do {
        std::cout << "Enter a message to send...\n" << std::endl;
        std::getline(std::cin, message);
        
    } while (run);
    
    
    return 0;
}
