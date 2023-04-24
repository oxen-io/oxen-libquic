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

void
make_echo_server_nullcert(std::shared_ptr<oxen::quic::Context> ctx, oxen::quic::TLSCert cert)
{
    std::string host{"127.0.0.1"};
    uint16_t port = 12345;

    ctx->listen_nullcert_test(host, port, cert);
};

void
make_oneshot_client_nullcert(std::shared_ptr<oxen::quic::Context> ctx, oxen::quic::TLSCert cert)
{
    std::string remote_host{"127.0.0.1"}, local_host{"127.0.0.1"};
    uint16_t remote_port{12345}, local_port{4400};
    char msg[40] = "Hello from the other siiiiiiiiiiiiiiide";

    ctx->send_oneshot_nullcert_test(local_host, local_port, remote_host, remote_port, cert, msg);
};

int main(void)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto servercert = oxen::quic::NullCert{}, 
        clientcert = oxen::quic::NullCert{};

    auto ctx = std::make_shared<oxen::quic::Context>();

    make_echo_server_nullcert(ctx, servercert);
    make_oneshot_client_nullcert(ctx, clientcert);

    ctx->get_quic()->loop()->run();

    ctx->shutdown_test();
    
    return 0;
}
