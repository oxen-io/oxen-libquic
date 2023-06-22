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
        ev_loop = uvw::loop::create();

        loop_thread = std::make_unique<std::thread>([this]() {
            while (not running)
            {};
            ev_loop->run();
            log::debug(log_cat, "Event Loop `run` returned, thread finished");
        });
        quic_manager = std::make_shared<Handler>(ev_loop, loop_thread->get_id(), *this);

        running.store(true);
    }

    Network::~Network()
    {
        close();
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

                // Destroy all our uv_udp_ts (their shared_ptr destructors will call close, and
                // actual freeing should happen in the next event loop iteration).
                mapped_client_addrs.clear();
                mapped_server_addrs.clear();

                if (loop_thread)
                {
                    // this does not reset the ev_loop shared_ptr, but rather "reset"s the underlying
                    // uvw::loop parent class uvw::emitter (unregisters all event listeners)
                    ev_loop->reset();
                    // FIXME: this walk breaks hard because uvw idiotically assumes without checking
                    // that it owns all libuv types, so our uv_udp_t's (which we have to use because
                    // uvw's udp_handle_t is completely broken when you turn RECVMMSG on) get mashed
                    // and dereferenced into the wrong pointer type in this call:
                    //
                    // ev_loop->walk([](auto&& h) { h.close(); });
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
            loop_thread->join();
            loop_thread.reset();
            ev_loop->close();
        }

        log::debug(log_cat, "Event loop shut down...");
    }

    int64_t receive_counter = 0;

    namespace
    {
        struct udp_data
        {
            bool server = true;
            std::shared_ptr<Handler> quic_manager;
            char buf[
#if !defined(OXEN_LIBQUIC_UDP_NO_RECVMMSG) && (defined(__linux__) || defined(__FreeBSD__))
                    max_bufsize * 8
#else
                    max_bufsize
#endif
            ];
        };

        extern "C" void recv_alloc(uv_handle_t* handle, size_t /*suggested_size*/, uv_buf_t* buf)
        {
            auto& data_buf = static_cast<udp_data*>(handle->data)->buf;
            buf->base = data_buf;
            buf->len = sizeof(data_buf);
        }
        // uvw's receive callback is completely broken w.r.t handling the RECVMMSG flag, so we do
        // our own C callback on the raw handle.  These warts with uvw come up so often, perhaps we
        // should just ditch uvw entirely?
        extern "C" void recv_callback(
                uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf_raw, const sockaddr* addr, unsigned flags)
        {
            if (nread > 0 || (nread == 0 && addr != nullptr))
            {
                receive_counter++;
                Packet pkt{};
                pkt.data = {reinterpret_cast<const std::byte*>(buf_raw->base), static_cast<size_t>(nread)};
                sockaddr_storage local_s_store;
                sockaddr* local_s = reinterpret_cast<sockaddr*>(&local_s_store);
                int namelen = sizeof(local_s_store);
                uv_udp_getsockname(handle, local_s, &namelen);
                pkt.path.local = local_s;
                assert(namelen == pkt.path.local.socklen());
                pkt.path.remote = addr;

                auto& data = *static_cast<udp_data*>(handle->data);
                auto& quic_manager = *data.quic_manager;

                log::trace(
                        log_cat,
                        "{} received packet from sender {} (size = {}) with message: \n{}",
                        data.server ? "Server" : "Client",
                        pkt.path.remote,
                        pkt.data.size(),
                        buffer_printer{pkt.data});
                log::trace(
                        log_cat,
                        "Searching {} mapping for local address {}",
                        data.server ? "server" : "client",
                        pkt.path.local);

                Endpoint* endpoint;
                if (data.server)
                    endpoint = quic_manager.find_server(pkt.path.local);
                else
                    endpoint = quic_manager.find_client(pkt.path.local);

                if (endpoint)
                    endpoint->handle_packet(pkt);
                else
                    log::warning(log_cat, "{} packet handling unsuccessful", data.server ? "Server" : "Client");
            }
            else if (nread == 0)
            {
                // This is libuv telling us its done with the recvmmsg batch
            }
            else
            {
                log::warning(log_cat, "recv_callback error {}", nread);
            }
        }
    }  // namespace

    std::shared_ptr<uv_udp_t> Network::start_udp_handle(uv_loop_t* loop, bool server, const Address& bind)
    {
        log::info(log_cat, "Starting new UDP handle on {}", bind);
        std::shared_ptr<uv_udp_t> udp{new uv_udp_t{}, [](uv_udp_t* udp) {
                                          auto* handle = reinterpret_cast<uv_handle_t*>(udp);
                                          if (uv_is_active(handle))
                                              uv_udp_recv_stop(udp);
                                          uv_close(handle, [](uv_handle_t* handle) {
                                              auto* udp = reinterpret_cast<uv_udp_t*>(handle);
                                              if (udp->data != nullptr)
                                                  delete static_cast<udp_data*>(udp->data);
                                              delete udp;
                                          });
                                      }};

        uv_udp_init_ex(
                loop,
                udp.get(),
#if !defined(OXEN_LIBQUIC_UDP_NO_RECVMMSG) && (defined(__linux__) || defined(__FreeBSD__))
                UV_UDP_RECVMMSG
#else
                0
#endif
        );
        udp->data = new udp_data{server, quic_manager};
        // binding is done here rather than after returning, so an already bound
        // uv_udp_t isn't bound to the same address twice
        int rv = uv_udp_bind(udp.get(), bind, 0);
        if (rv != 0)
            throw std::runtime_error{"Failed to bind UDP handle: " + std::string{uv_strerror(rv)}};
        rv = uv_udp_recv_start(udp.get(), recv_alloc, recv_callback);
        if (rv != 0)
            throw std::runtime_error{"Failed to start listening on UDP handle: " + std::string{uv_strerror(rv)}};
        return udp;
    }

    std::shared_ptr<uv_udp_t> Network::handle_mapping(bool server, const Address& local)
    {
        auto& udp = (server ? mapped_server_addrs : mapped_client_addrs)[local];

        if (!udp)
        {
            log::trace(log_cat, "Creating dedicated {} uv_udp_t on {}...", server ? "server" : "client", local);
            udp = start_udp_handle(quic_manager->loop()->raw(), server, local);
        }

        return udp;
    }

}  // namespace oxen::quic
