#include <catch2/catch_test_macros.hpp>
#include <thread>

#include "quic.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("005: Chunked stream sending", "[005][chunked]")
    {
        logger_config();

        Network test_net{};

        std::mutex recv_mut;
        std::string received;
        auto stream_callback = [&](Stream& s, bstring_view data) {
            std::lock_guard lock{recv_mut};
            received.append(reinterpret_cast<const char*>(data.data()), data.size());
        };

        opt::server_tls server_tls{"./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s};
        opt::client_tls client_tls{"./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s};

        opt::local_addr server_local{"127.0.0.1"s, static_cast<uint16_t>(5500)};
        opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
        opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

        log::debug(log_cat, "Calling 'server_listen'...");
        auto server = test_net.server_listen(server_local, server_tls, stream_callback);

        log::debug(log_cat, "Calling 'client_connect'...");
        auto client = test_net.client_connect(client_local, client_remote, client_tls);

        std::thread ev_thread{[&]() { test_net.run(); }};

        auto stream = client->open_stream();
        stream->send("HELLO!"s);
        int i = 0;
        auto next_chunk = [&] {
            log::critical(log_cat, "getting next chunk ({})", i);
            if (i++ < 10)
                return fmt::format("[CHUNK-{}]", i);
            return ""s;
        };
        auto post_chunk = [&] {
            log::critical(log_cat, "All chunks done!");
            stream->send("Goodbye."s);
        };

        stream->send_chunks<std::string>(next_chunk, post_chunk);

        std::this_thread::sleep_for(250ms);

        {
            std::lock_guard lock{recv_mut};
            CHECK(received ==
                  "HELLO![CHUNK-1][CHUNK-2][CHUNK-3][CHUNK-4][CHUNK-5][CHUNK-6][CHUNK-7][CHUNK-8][CHUNK-9][CHUNK-10]"
                  "Goodbye.");
        }

        test_net.ev_loop->stop();
        ev_thread.join();
    };
}  // namespace oxen::quic::test
