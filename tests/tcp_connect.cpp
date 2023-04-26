#include "crypto.hpp"
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

    auto ctx = std::make_shared<oxen::quic::Network>();
    oxen::quic::Address local{"127.0.0.1", 4400},
        remote{"127.0.0.1", 12345};

    std::string message;

    ctx->udp_connect(local, remote, nullptr, nullptr, oxen::quic::NullCert{});
    
    do {
        std::cout << "Enter a message to send...\n" << std::endl;
        std::getline(std::cin, message);
        
    } while (run);
    
    
    return 0;
}
