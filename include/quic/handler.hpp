#pragma once

extern "C"
{
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
}

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>
#include <uvw.hpp>
#include <vector>

#include "crypto.hpp"
#include "utils.hpp"

using oxen::log::slns::source_location;

namespace oxen::quic
{
    template <typename... T>
    void loop_trace_log(
            const log::logger_ptr& cat_logger,
            [[maybe_unused]] const source_location& location,
            [[maybe_unused]] fmt::format_string<T...> fmt,
            [[maybe_unused]] T&&... args)
    {
#if defined(NDEBUG) && !defined(OXEN_LOGGING_RELEASE_TRACE)
        // Using [[maybe_unused]] on the *first* ctor argument breaks gcc 8/9
        (void)cat_logger;
#else
        if (cat_logger)
            cat_logger->log(log::detail::spdlog_sloc(location), log::Level::trace, fmt, std::forward<T>(args)...);
#endif
    }

    // class Client;
    class Stream;
    class Client;
    class Server;
    class Network;
    class ClientContext;
    class ServerContext;

    class Handler
    {
        friend class Network;

        bool in_event_loop() const;

      public:
        explicit Handler(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id loop_thread_id, Network& net);
        ~Handler();

        Network& net;

        std::shared_ptr<uvw::udp_handle> universal_handle;
        Address default_local{"127.0.0.1", 4433};
        std::shared_ptr<uvw::async_handle> io_trigger;
        std::shared_ptr<uvw::loop> ev_loop;

        std::shared_ptr<uvw::loop> loop();

        void client_call_async(async_callback_t async_cb);

        void call_soon(std::function<void(void)> f, source_location src = source_location::current());

        template <typename Callable>
        void call(Callable&& f, source_location src = source_location::current())
        {
            if (in_event_loop())
            {
                loop_trace_log(log_cat, src, "Event loop calling `{}`", src.function_name());
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f), std::move(src));
            }
        }

        void process_job_queue();

        void client_close();

        void close_all();

      private:
        // Tracks client endpoints that are currently being managed by handler object
        std::vector<std::shared_ptr<ClientContext>> clients;
        // Maps server endpoints that are currently being managed by handler object
        //  - key: Address{local_addr}
        //  - value: pointer to server context object
        //
        // For example, when a user listens to 127.0.0.1:4433, the ClientManager ptr
        // will be indexed to Address{"127.0.0.1", "5440"}
        std::unordered_map<Address, std::shared_ptr<ServerContext>> servers;

        ///	keep ev loop open for cleanup
        std::shared_ptr<int> keep_alive = std::make_shared<int>(0);

        using Job = std::pair<std::function<void()>, source_location>;

        std::thread::id loop_thread_id;
        std::shared_ptr<uvw::async_handle> job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;
    };
}  // namespace oxen::quic
