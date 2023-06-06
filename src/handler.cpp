#include "handler.hpp"

extern "C"
{
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
}

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <thread>
#include <uvw.hpp>

#include "client.hpp"
#include "connection.hpp"
#include "context.hpp"
#include "crypto.hpp"
#include "endpoint.hpp"
#include "network.hpp"
#include "server.hpp"

namespace oxen::quic
{
    Handler::Handler(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id loop_thread_id, Network& net) :
            net{net}, loop_thread_id{loop_thread_id}
    {
        ev_loop = loop_ptr;
        universal_handle = ev_loop->resource<uvw::udp_handle>();

        universal_handle->bind(default_local);
        net.mapped_client_addrs.emplace(Address{default_local}, universal_handle);

        if (job_waker = ev_loop->resource<uvw::AsyncHandle>(); !job_waker)
            throw std::runtime_error{"Failed to create job queue uvw async handle"};

        job_waker->on<uvw::AsyncEvent>([this](const auto&, auto&) { process_job_queue(); });

        log::info(log_cat, "{}", (ev_loop) ? "Event loop successfully created" : "Error: event loop creation failed");
    }

    Handler::~Handler()
    {
        log::debug(log_cat, "Shutting down tunnel manager...");

        for (const auto& itr : clients)
            itr->client->~Client();

        for (const auto& itr : servers)
            itr.second->server->~Server();

        if (ev_loop)
        {
            ev_loop->walk(uvw::overloaded{[](uvw::udp_handle&& h) { h.close(); }, [](auto&&) {}});
            ev_loop->reset();
            ev_loop->stop();
            ev_loop->close();
            log::debug(log_cat, "Event loop shut down...");
        }

        clients.clear();
        servers.clear();
    }

    std::shared_ptr<uvw::loop> Handler::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }

    bool Handler::in_event_loop() const
    {
        return std::this_thread::get_id() == loop_thread_id;
    }

    void Handler::call_soon(std::function<void(void)> f)
    {
        log::trace(log_cat, "{}", __PRETTY_FUNCTION__);
        std::lock_guard<std::mutex> lock{job_queue_mutex};
        job_queue.push(std::move(f));
        job_waker->send();
    }

    void Handler::process_job_queue()
    {
        assert(in_event_loop());

        decltype(job_queue) swapped_queue;

        {
            std::lock_guard<std::mutex> lock{job_queue_mutex};
            job_queue.swap(swapped_queue);
        }

        while (not swapped_queue.empty())
        {
            auto f = swapped_queue.front();
            swapped_queue.pop();
            f();
        }
    }

    void Handler::client_call_async(async_callback_t async_cb)
    {
        for (const auto& itr : clients)
        {
            itr->client->call_async_all(async_cb);
        }
    }

    void Handler::client_close()
    {
        for (const auto& c : clients)
        {}
    }

    void Handler::close_all()
    {
        call([this]() {
            if (!clients.empty())
            {
                for (const auto& ctx : clients)
                    ctx->client->close_conns();
            }
        });
    }

}  // namespace oxen::quic
