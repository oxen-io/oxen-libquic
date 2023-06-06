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

namespace oxen::quic
{
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

        void call_soon(std::function<void(void)> f);

        template <typename Callable>
        void call(Callable&& f)
        {
            if (in_event_loop())
                f();
            else
                call_soon(std::forward<Callable>(f));
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

        std::thread::id loop_thread_id;
        std::shared_ptr<uvw::AsyncHandle> job_waker;
        std::queue<std::function<void()>> job_queue;
        std::mutex job_queue_mutex;
    };
}  // namespace oxen::quic
