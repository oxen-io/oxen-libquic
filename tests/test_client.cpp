/*
    Test client binary
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

    Network client_net{};
    auto msg = "hello from the other siiiii-iiiiide"_bsv;
    log::trace(log_cat, "send message size = {}", msg.size());

    opt::client_tls client_tls{
        0, 
        "/home/dan/oxen/libquicinet/tests/clientkey.pem"s, 
        "/home/dan/oxen/libquicinet/tests/clientcert.pem"s, 
        "/home/dan/oxen/libquicinet/tests/servercert.pem"s,
        ""s,
        nullptr};

    opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
    opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

    log::debug(log_cat, "Calling 'client_connect'...");
    auto client = client_net.client_connect(client_local, client_remote, client_tls);

    std::thread ev_thread{[&](){ 
        client_net.ev_loop->run();

        size_t counter = 0;
        do
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            if (++counter % 30 == 0)
                std::cout << "waiting..." << "\n";
        } while (run);
    }};

    log::debug(log_cat, "Main thread call");
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    std::thread async_thread{[&](){
        log::debug(log_cat, "Async thread called");
        auto stream = client->open_stream();
        stream->send(msg);
    }};
    
    size_t counter = 0;
    do
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        if (++counter % 30 == 0)
            std::cout << "waiting..." << "\n";
    } while (run);

    async_thread.join();
    ev_thread.join();

    return 0;
}
