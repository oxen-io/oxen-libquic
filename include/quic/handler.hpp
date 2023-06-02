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
#include <queue>
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

      public:
        explicit Handler(std::shared_ptr<uvw::Loop> loop_ptr, Network& net);
        ~Handler();

        Network& net;

        std::shared_ptr<uvw::UDPHandle> universal_handle;
        Address default_local{"127.0.0.1", 4433};
        std::shared_ptr<uvw::AsyncHandle> io_trigger;
        std::shared_ptr<uvw::Loop> ev_loop;

        std::shared_ptr<uvw::Loop> loop();

        void client_call_async(async_callback_t async_cb);

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
    };
}  // namespace oxen::quic
