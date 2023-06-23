#include "network.hpp"

#include <memory>
#include <oxen/log.hpp>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <uvw.hpp>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    Network::Network(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id thread_id) :
            ev_loop{loop_ptr}, loop_thread_id{thread_id}
    {
        assert(ev_loop);
        log::trace(log_cat, "Beginning network context creation with pre-existing ev loop thread");

        if (job_waker = ev_loop->resource<uvw::async_handle>(); !job_waker)
            throw std::runtime_error{"Failed to create job queue uvw async handle"};

        job_waker->on<uvw::async_event>([this](const auto&, const auto&) { process_job_queue(); });

        running.store(true);
    }

    Network::Network()
    {
        log::trace(log_cat, "Beginning network context creation with new ev loop thread");
        ev_loop = uvw::loop::create();

        loop_thread = std::make_unique<std::thread>([this]() {
            while (not running)
            {};
            ev_loop->run();
            log::debug(log_cat, "Event Loop `run` returned, thread finished");
        });

        loop_thread_id = loop_thread->get_id();

        if (job_waker = ev_loop->resource<uvw::async_handle>(); !job_waker)
            throw std::runtime_error{"Failed to create job queue uvw async handle"};

        job_waker->on<uvw::async_event>([this](const auto&, const auto&) { process_job_queue(); });

        running.store(true);
    }

    Network::~Network()
    {
        close();
    }

    std::shared_ptr<Endpoint> Network::endpoint(const Address& local_addr)
    {
        if (auto [it, added] = endpoint_map.emplace(local_addr, nullptr); !added)
        {
            log::info(log_cat, "Endpoint already exists for listening address {}", local_addr);
            return it->second;
        }
        else
        {
            it->second = std::move(std::make_shared<Endpoint>(*this, local_addr));
            return it->second;
        }
    }

    void Network::close()
    {
        if (not running.exchange(false))
            return;

        log::info(log_cat, "Shutting down context...");

        std::promise<void> p;
        auto f = p.get_future();

        call([this, &p]() {
            try
            {
                close_all();

                // Destroy all our uv_udp_ts (their shared_ptr destructors will call close, and
                // actual freeing should happen in the next event loop iteration).
                endpoint_map.clear();

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

    namespace
    {
        struct udp_data
        {
            Endpoint& ep;
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
                auto& endpoint = data.ep;

                log::trace(
                        log_cat,
                        "Endpoint received packet from sender {} (size = {}) with message: \n{}",
                        pkt.path.remote,
                        pkt.data.size(),
                        buffer_printer{pkt.data});

                endpoint.handle_packet(pkt);
            }
            else if (nread == 0)
            {
                // This is libuv telling us its done with the recvmmsg batch (libuv sux)
            }
            else
            {
                log::warning(log_cat, "recv_callback error {}", nread);
            }
        }
    }  // namespace

    std::shared_ptr<uv_udp_t> Network::start_udp_handle(uv_loop_t* loop, const Address& bind, Endpoint& ep)
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

        udp->data = new udp_data{ep};
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

    std::shared_ptr<uv_udp_t> Network::map_udp_handle(const Address& local, Endpoint& ep)
    {
        if (auto itr = handle_map.find(const_cast<Address&>(local)); itr != handle_map.end())
            return itr->second;

        log::trace(log_cat, "Creating dedicated uv_udp_t handle listening on {}...", local);

        auto udp = start_udp_handle(loop()->raw(), local, ep);
        handle_map[const_cast<Address&>(local)] = udp;

        return udp;
    }

    std::shared_ptr<uvw::loop> Network::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }

    bool Network::in_event_loop() const
    {
        return std::this_thread::get_id() == loop_thread_id;
    }

    // NOTE (Tom): when closing, when to stop accepting new jobs and stop/close async handle?
    void Network::call_soon(std::function<void(void)> f, source_location src)
    {
        loop_trace_log(log_cat, src, "Event loop queueing `{}`", src.function_name());

        std::lock_guard<std::mutex> lock{job_queue_mutex};

        job_queue.emplace(std::move(f), std::move(src));

        log::trace(log_cat, "Event loop now has {} jobs queued", job_queue.size());

        job_waker->send();
    }

    void Network::process_job_queue()
    {
        log::trace(log_cat, "Event loop processing job queue");
        assert(in_event_loop());

        decltype(job_queue) swapped_queue;

        {
            std::lock_guard<std::mutex> lock{job_queue_mutex};
            job_queue.swap(swapped_queue);
        }

        while (not swapped_queue.empty())
        {
            auto job = swapped_queue.front();
            swapped_queue.pop();
            const auto& src = job.second;
            loop_trace_log(log_cat, src, "Event loop calling `{}`", src.function_name());
            job.first();
        }
    }

    // TODO (Tom): for graceful shutdown, how best to wait until clients and servers have properly disconnected
    void Network::close_all()
    {
        call([this]() {
            if (!endpoint_map.empty())
            {
                for (const auto& ep : endpoint_map)
                    ep.second->close_conns();
            }
        });
    }

}  // namespace oxen::quic
