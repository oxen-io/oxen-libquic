#include "network.hpp"

#include <memory>
#include <oxen/log.hpp>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <uvw.hpp>

#include "connection.hpp"
#include "context.hpp"
#include "handler.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    Network::Network(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id loop_thread_id) : ev_loop{loop_ptr}
    {
        assert(ev_loop);
        log::trace(log_cat, "Beginning context creation");

        quic_manager = std::make_shared<Handler>(ev_loop, loop_thread_id, *this);
    }

    Network::Network()
    {
        log::trace(log_cat, __PRETTY_FUNCTION__);
        ev_loop = uvw::Loop::create();

        signal_config();  // TODO: probably remove this, as the library user should handle signals

        loop_thread = std::make_unique<std::thread>([this]() { ev_loop->run(); });
        running.store(true);
        quic_manager = std::make_shared<Handler>(ev_loop, loop_thread->get_id(), *this);
    }

    Network::~Network()
    {
        close();
    }

    void Network::signal_config()
    {
        auto signal = ev_loop->resource<uvw::signal_handle>();
        signal->on<uvw::error_event>([](const auto&, auto&) { log::warning(log_cat, "Error event in signal handle"); });
        signal->on<uvw::signal_event>([&](const auto&, auto&) {
            log::debug(log_cat, "Signal event triggered in signal handle");
            ev_loop->walk(uvw::overloaded{
                    [](uvw::udp_handle&& h) {
                        h.close();
                        h.stop();
                    },
                    [](uvw::async_handle&& h) { h.close(); },
                    [](auto&&) {}});

            signal->stop();

            ev_loop->reset();
            ev_loop->stop();
            ev_loop->close();
        });

        if (signal->init())
            signal->start(SIGINT);
    }

    void Network::close()
    {
        if (not running.exchange(false))
            return;

        log::info(log_cat, "Shutting down context...");

        std::promise<void> p;
        auto f = p.get_future();
        quic_manager->call([this, &p]() {
            try
            {
                quic_manager->close_all();

                for (auto& [addr, handle] : mapped_client_addrs)
                {
                    auto s = handle->sock();
                    log::debug(log_cat, "closing client UDPHandle bound to {}:{}", s.ip, s.port);
                    handle->close();
                }
                for (auto& [addr, handle] : mapped_server_addrs)
                {
                    auto s = handle->sock();
                    log::debug(log_cat, "closing server UDPHandle bound to {}:{}", s.ip, s.port);
                    handle->close();
                }

                if (loop_thread)
                {
                    // this does not reset the ev_loop shared_ptr, but rather "reset"s the underlying
                    // uvw::loop parent class uvw::emitter (unregisters all event listeners)
                    ev_loop->clear();
                    ev_loop->stop();
                }
                p.set_value();
            }
            catch (...)
            {
                p.set_exception(std::current_exception());
            }
        });
        f.get();

        if (loop_thread)
        {
            quic_manager->call([this](){
                ev_loop->walk([](auto&& h) { h.close(); });
                ev_loop->stop();
            });
            loop_thread->join();
            loop_thread.reset();
            ev_loop->close();
        }

        log::debug(log_cat, "Event loop shut down...");
    }

    void Network::configure_client_handle(std::shared_ptr<uvw::udp_handle> handle)
    {
        // client receive data
        handle->on<uvw::udp_data_event>([&](const uvw::udp_data_event& event, uvw::udp_handle& handle) {
            bstring_view data{reinterpret_cast<const std::byte*>(event.data.get()), event.length};

            Packet pkt{.path = Path{handle.sock(), event.sender}, .data = data};

            log::trace(
                    log_cat,
                    "Client received packet from sender {}:{} (size = {}) with message: \n{}",
                    pkt.path.remote.ip.data(),
                    pkt.path.remote.port,
                    data.size(),
                    buffer_printer{data});
            log::trace(
                    log_cat,
                    "Searching client mapping for local address {}:{}",
                    pkt.path.local.ip.data(),
                    pkt.path.local.port);

            for (auto ctx : quic_manager->clients)
            {
                if (ctx->local == handle.sock())
                {
                    ctx->client->handle_packet(pkt);
                    return;
                }
            }
            log::warning(log_cat, "Client handle forwarding unsuccessful");
        });
    }

    void Network::configure_server_handle(std::shared_ptr<uvw::udp_handle> handle)
    {
        // server receive data
        handle->on<uvw::udp_data_event>([&](const uvw::udp_data_event& event, uvw::udp_handle& handle) {
            bstring_view data{reinterpret_cast<const std::byte*>(event.data.get()), event.length};

            Packet pkt{.path = Path{handle.sock(), event.sender}, .data = data};

            log::trace(
                    log_cat,
                    "Server received packet from sender {}:{} (size = {}) with message: \n{}",
                    pkt.path.remote.ip.data(),
                    pkt.path.remote.port,
                    data.size(),
                    buffer_printer{data});
            log::trace(
                    log_cat,
                    "Searching server mapping for local address {}:{}",
                    pkt.path.local.ip.data(),
                    pkt.path.local.port);

            auto itr = quic_manager->servers.find(pkt.path.local);

            if (itr != quic_manager->servers.end())
            {
                itr->second->server->handle_packet(pkt);
                return;
            }
            else
                log::warning(log_cat, "Server handle forwarding unsuccessful");
        });
    }

    std::shared_ptr<uvw::udp_handle> Network::handle_client_mapping(Address& local)
    {
        auto q = mapped_client_addrs.find(local);

        if (q == mapped_client_addrs.end())
        {
            log::trace(log_cat, "Creating dedicated client udp_handle...");
            auto handle = quic_manager->loop()->resource<uvw::udp_handle>();
            configure_client_handle(handle);
            // binding is done here rather than after returning, so an already bound
            // UDPhandle isn't bound to the same address twice
            handle->bind(local);
            handle->recv();
            mapped_client_addrs[local] = handle;
            return handle;
        }

        return q->second;
    }

    std::shared_ptr<uvw::udp_handle> Network::handle_server_mapping(Address& local)
    {
        auto q = mapped_server_addrs.find(local);

        if (q == mapped_server_addrs.end())
        {
            log::trace(log_cat, "Creating dedicated server udp_handle...");
            auto handle = quic_manager->loop()->resource<uvw::udp_handle>();
            configure_server_handle(handle);
            handle->bind(local);
            handle->recv();
            mapped_server_addrs[local] = handle;
            return handle;
        }

        return q->second;
    }
}  // namespace oxen::quic
