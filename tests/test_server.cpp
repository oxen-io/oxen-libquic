/*
    Test server binary
*/

#include "quic.hpp"

#include <thread>


using namespace oxen::quic;


bool run{true};

void
signal_handler(int)
{
    run = false;
}


int main(int argc, char* argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    logger_config();

    Network server_net{};

    opt::server_tls server_tls{
        "/home/dan/oxen/libquicinet/tests/serverkey.pem"s, 
        "/home/dan/oxen/libquicinet/tests/servercert.pem"s, 
        "/home/dan/oxen/libquicinet/tests/clientcert.pem"s, 
        1};

    opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};

    log::debug(log_cat, "Calling 'server_listen'...");
    auto server = server_net.server_listen(server_local, server_tls);

    log::debug(log_cat, "Starting event loop...");
    server_net.ev_loop->run();

    return 0;
}

