/*
    Test server binary
*/

#include <quic.hpp>
#include <thread>

using namespace oxen::quic;

bool run{true};

void signal_handler(int)
{
    run = false;
}

int main(int argc, char* argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    logger_config();

    Network server_net{};

    auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

    opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};

    stream_open_callback_t stream_cb = [&](Stream& s) {
        log::debug(log_cat, "Stream open callback called");
        return 0;
    };

    log::debug(log_cat, "Calling 'server_listen'...");
    auto server = server_net.server_listen(server_local, server_tls, stream_cb);

    size_t counter = 0;
    do
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        if (++counter % 30 == 0)
            std::cout << "waiting..."
                      << "\n";
    } while (run);

    return 0;
}
