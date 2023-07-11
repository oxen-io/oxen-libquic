#include <catch2/catch_test_macros.hpp>
#include <iterator>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("005 - Chunked stream sending: Config", "[005][chunked][config]")
    {
        Network test_net{};

        std::mutex recv_mut;
        std::string received;
        std::atomic<int> data_check{0};
        std::atomic<int> index{0};

        std::vector<std::promise<bool>> receive_promises{5};
        std::vector<std::future<bool>> receive_futures{5};

        for (int i = 0; i < 5; ++i)
            receive_futures[i] = receive_promises[i].get_future();

        stream_data_callback io_data_cb = [&](Stream&, bstring_view data) {
            std::lock_guard lock{recv_mut};
            received.append(reinterpret_cast<const char*>(data.data()), data.size());

            try
            {
                receive_promises.at(index).set_value(true);
                ++index;
                data_check += 1;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, 5509};
        opt::local_addr client_local{"127.0.0.1"s, 4414};
        opt::remote_addr client_remote{"127.0.0.1"s, 5509};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, io_data_cb));

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        auto stream = conn_interface->get_new_stream();
        stream->send("HELLO!"s);

        int i = 0;
        constexpr size_t parallel_chunks = 2;
        std::array<std::vector<char>, parallel_chunks> bufs;

        REQUIRE_THROWS_AS(
                stream->send_chunks(
                        [&](const Stream& s) {
                            log::info(log_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                            if (i++ < 3)
                                return fmt::format("[CHUNK-{}]", i);
                            i--;
                            return ""s;
                        },
                        [&](Stream& s) {
                            auto pointer_chunks = [&](const Stream& s) -> std::vector<char>* {
                                log::info(log_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                                if (i++ < 6)
                                {
                                    auto& vec = bufs[i % parallel_chunks];
                                    vec.clear();
                                    fmt::format_to(std::back_inserter(vec), "[Chunk-{}]", i);
                                    return &vec;
                                }
                                i--;
                                return nullptr;
                            };

                            s.send_chunks(
                                    pointer_chunks,
                                    [&](Stream& s) {
                                        auto smart_ptr_chunks = [&](const Stream& s) -> std::unique_ptr<std::vector<char>> {
                                            log::info(log_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                                            if (i++ >= 10)
                                                return nullptr;
                                            auto vec = std::make_unique<std::vector<char>>();
                                            fmt::format_to(std::back_inserter(*vec), "[chunk-{}]", i);
                                            return vec;
                                        };
                                        s.send_chunks(
                                                smart_ptr_chunks,
                                                [&](Stream& s) {
                                                    // (Lokinet RPC was here)
                                                    log::info(log_cat, "All chunks done!");
                                                    s.send("Goodbye."s);
                                                },
                                                parallel_chunks);
                                    },
                                    parallel_chunks);
                        },
                        0),
                std::logic_error);  // setting parallel_chunks to 0 wont compile due to the modulus operation

        for (auto& f : receive_futures)
            REQUIRE(f.valid());

        {
            std::lock_guard lock{recv_mut};
            REQUIRE_FALSE(
                    received ==
                    "HELLO![CHUNK-1][CHUNK-2][CHUNK-3][Chunk-4][Chunk-5][Chunk-6][chunk-7][chunk-8][chunk-9][chunk-10]"
                    "Goodbye.");
        }

        REQUIRE_FALSE(data_check == 5);
        test_net.close();
    };

    TEST_CASE("005 - Chunked stream sending: Execution", "[005][chunked][excecute]")
    {
        Network test_net{};

        std::mutex recv_mut;
        std::string received;
        std::atomic<int> data_check{0};
        std::atomic<int> index{0};

        std::vector<std::promise<bool>> receive_promises{5};
        std::vector<std::future<bool>> receive_futures{5};

        for (int i = 0; i < 5; ++i)
            receive_futures[i] = receive_promises[i].get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view data) {
            std::lock_guard lock{recv_mut};
            received.append(reinterpret_cast<const char*>(data.data()), data.size());

            try
            {
                receive_promises.at(index).set_value(true);
                ++index;
                data_check += 1;
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{"127.0.0.1"s, 5510};
        opt::local_addr client_local{"127.0.0.1"s, 4415};
        opt::remote_addr client_remote{"127.0.0.1"s, 5510};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_data_cb));

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        auto stream = conn_interface->get_new_stream();
        stream->send("HELLO!"s);

        int i = 0;
        constexpr size_t parallel_chunks = 2;
        std::array<std::vector<char>, parallel_chunks> bufs;

        stream->send_chunks(
                [&](const Stream& s) {
                    log::info(log_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                    if (i++ < 3)
                        return fmt::format("[CHUNK-{}]", i);
                    i--;
                    return ""s;
                },
                [&](Stream& s) {
                    auto pointer_chunks = [&](const Stream& s) -> std::vector<char>* {
                        log::info(log_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                        if (i++ < 6)
                        {
                            auto& vec = bufs[i % parallel_chunks];
                            vec.clear();
                            fmt::format_to(std::back_inserter(vec), "[Chunk-{}]", i);
                            return &vec;
                        }
                        i--;
                        return nullptr;
                    };

                    s.send_chunks(
                            pointer_chunks,
                            [&](Stream& s) {
                                auto smart_ptr_chunks = [&](const Stream& s) -> std::unique_ptr<std::vector<char>> {
                                    log::info(log_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                                    if (i++ >= 10)
                                        return nullptr;
                                    auto vec = std::make_unique<std::vector<char>>();
                                    fmt::format_to(std::back_inserter(*vec), "[chunk-{}]", i);
                                    return vec;
                                };
                                s.send_chunks(
                                        smart_ptr_chunks,
                                        [&](Stream& s) {
                                            // (Lokinet RPC was here)
                                            log::info(log_cat, "All chunks done!");
                                            s.send("Goodbye."s);
                                        },
                                        parallel_chunks);
                            },
                            parallel_chunks);
                },
                parallel_chunks);

        for (auto& f : receive_futures)
            REQUIRE(f.get());

        {
            std::lock_guard lock{recv_mut};
            REQUIRE(received ==
                    "HELLO![CHUNK-1][CHUNK-2][CHUNK-3][Chunk-4][Chunk-5][Chunk-6][chunk-7][chunk-8][chunk-9][chunk-10]"
                    "Goodbye.");
        }

        REQUIRE(data_check == 5);
        test_net.close();
    };
}  // namespace oxen::quic::test
