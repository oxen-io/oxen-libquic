/*
    Test client binary
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

    Network client_net{};
    auto msg = "hello from the other siiiii-iiiiide"_bsv;

    auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

    opt::local_addr client_a_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
    opt::local_addr client_b_local{"127.0.0.1"s, static_cast<uint16_t>(4422)};
    opt::local_addr client_c_local{"127.0.0.1"s, static_cast<uint16_t>(4444)};
    opt::local_addr client_d_local{"127.0.0.1"s, static_cast<uint16_t>(4466)};
    opt::remote_addr client_a_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
    opt::remote_addr client_b_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
    opt::remote_addr client_c_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
    opt::remote_addr client_d_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

    log::debug(log_cat, "Calling 'client_connect'...");
    auto client_a = client_net.client_connect(client_a_local, client_a_remote, client_tls);
    auto client_b = client_net.client_connect(client_b_local, client_b_remote, client_tls);

    log::debug(log_cat, "Main thread call");
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    std::thread async_thread_a{[&]() {
        log::debug(log_cat, "Async thread 1 called");

        auto client_c = client_net.client_connect(client_c_local, client_c_remote, client_tls);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        auto stream_a = client_a->open_stream();
        stream_a->send(msg);

        auto stream_b = client_b->open_stream();
        stream_b->send(msg);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        auto stream_c = client_c->open_stream();
        stream_c->send(msg);
    }};

    std::thread async_thread_b{[&]() {
        log::debug(log_cat, "Async thread 2 called");

        auto client_d = client_net.client_connect(client_d_local, client_d_remote, client_tls);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        auto stream_d = client_d->open_stream();
        stream_d->send(msg);
    }};

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    size_t counter = 0;
    do
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        if (++counter % 30 == 0)
            std::cout << "waiting..."
                      << "\n";
    } while (run);

    async_thread_a.join();
    async_thread_b.join();

    return 0;
}
