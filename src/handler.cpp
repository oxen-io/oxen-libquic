#include "handler.hpp"
#include "context.hpp"
#include "network.hpp"
#include "crypto.hpp"
#include "server.hpp"
#include "client.hpp"
#include "endpoint.hpp"
#include "connection.hpp"

#include <uvw.hpp>

#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>


namespace oxen::quic
{
    // Takes data from the UDP connection and pushes it down the quic tunnel
    void
    on_outgoing_data(uvw::DataEvent& event, uvw::UDPHandle& client)
    {
        auto stream = client.data<Stream>();
        assert(stream);
        std::string data{event.data.get(), event.length};
        auto peer = client.peer();

       log::trace(log_cat, "%s:%u → %s", peer.ip.c_str(), peer.port, data.c_str());
        // Steal the buffer from the DataEvent's unique_ptr<char[]>
        stream->append_buffer(reinterpret_cast<const std::byte*>(event.data.release()), event.length);
        if (stream->used() >= PAUSE_SIZE)
        {
            log::debug(log_cat, "QUIC tunnel is congested (have {} bytes in flight); pausing local udp connection reading",
                stream->used());
            client.stop();
            stream->when_available([](Stream& s) {
                auto client = s.get_user_data<uvw::UDPHandle>();
                if (s.used() < PAUSE_SIZE)
                {
                    log::debug(log_cat, "QUIC tunnel is no longer congested; resuming udp connection reading");
                    // TODO: think about this
                    client->recv();
                    return true;
                }
                return false;
            });
        }
        else
        {
            log::debug(log_cat, "Queued {} bytes", event.length);
        }
    }


    // TOFIX: THIS DUDE
    // Received data from the quic tunnel and sends it to the udp connection
    void
    on_incoming_data(Stream& stream, bstring_view bdata)
    {
        auto udp = stream.udp_handle;

        if (!udp)
            return;
        
        std::string_view data{reinterpret_cast<const char*>(bdata.data(), bdata.size())};
        if (data.empty())
            return;

        auto peer = udp->peer();

        /*
        auto udp = stream.get_user_data<uvw::UDPHandle>();
        if (!udp)
            return;  // TCP connection is gone, which would have already sent a stream close, so just
                    // drop it.

        std::string data{reinterpret_cast<const char*>(bdata.data()), bdata.size()};
        auto peer = udp->peer();
       log::trace(log_cat, "%s:%u ← lokinet %s", peer.ip.c_str(), peer.port, data.c_str());

        if (data.empty())
            return;

        // Try first to write immediately from the existing buffer to avoid needing an
        // allocation and copy:
        auto written = udp->tryWrite(const_cast<char*>(data.data()), data.size());
        if (written < (int)data.size())
        {
            data.erase(0, written);

            auto wdata = std::make_unique<char[]>(data.size());
            std::copy(data.begin(), data.end(), wdata.get());
            udp->write(std::move(wdata), data.size());
        }
        */
    }


    void
    close_udp_pair(Stream& st, std::optional<uint64_t>)
    {
        if (auto udp = st.udp_handle)
        {
            log::debug(log_cat, "Closing UDP connection");
            udp->close();
        }
    };


    void
    install_stream_forwarding(uvw::UDPHandle& udp, Stream& stream)
    {
        udp.data(stream.shared_from_this());
        auto weak_conn = stream.get_conn().weak_from_this();

        udp.clear();  // Clear any existing initial event handlers

        udp.on<uvw::CloseEvent>([weak_conn = std::move(weak_conn)](auto&, uvw::UDPHandle& c) 
        {
            // This fires sometime after we call `close()` to signal that the close is done.
            if (auto stream = c.data<Stream>())
            {
                log::info(log_cat, "Local UDP connection closed, closing associated quic stream {}", stream->stream_id);

                // There is an awkwardness with Stream ownership, so make sure the Connection
                // which it holds a reference to still exists, as stream->close will segfault
                // otherwise
                if (auto locked_conn = weak_conn.lock())
                    stream->close(-1);
                stream->set_user_data(nullptr);
            }
            c.data(nullptr);
        });
        udp.on<uvw::EndEvent>([](auto&, uvw::UDPHandle& c) {
            // This fires on eof, most likely because the other side of the TCP connection closed it.
            log::warning(log_cat, "Error: EOF on connection to {}:{}", c.peer().ip.c_str(), c.peer().port);
            c.close();
        });
        udp.on<uvw::ErrorEvent>([](const uvw::ErrorEvent& e, uvw::UDPHandle& udp) {
            log::warning(log_cat, "ErrorEvent[{}:{}] on connection with {}:{}, shutting down quic stream",
                e.name(), e.what(), udp.peer().ip.c_str(), udp.peer().port);

            if (auto stream = udp.data<Stream>())
            {
                stream->close(-1);
                stream->set_user_data(nullptr);
                udp.data(nullptr);
            }
        });
        udp.on<uvw::DataEvent>(on_outgoing_data);
        stream.data_callback = on_incoming_data;
        stream.close_callback = close_udp_pair;
    }


    void
    initial_client_data_handler(uvw::UDPHandle& client, Stream& stream, bstring data)
    {
        if (data.empty())
            return;
        client.clear();
        if (auto b0 = data[0]; b0 == CONNECT_INIT)
        {
            client.recv();
            install_stream_forwarding(client, stream);

            if (data.size() > 1)
            {
                data.erase(0, 1);
                stream.data_callback(stream, data);
            }
        }
        else
        {
            log::debug(log_cat, "Error: remote connection returned invalid initial byte; dropping");
            stream.close(ERROR_BAD_INIT);
            client.close();
        }

        stream.io_ready();
    }


    void
    initial_client_close_handler(uvw::UDPHandle& client, Stream& stream, std::optional<uint64_t> error_code)
    {
        if (error_code && *error_code == ERROR_CONNECT)
            log::warning(log_cat, "Error: Remote UDP connection failed, closing local connection");
        else
            log::info(log_cat, "Stream connection closed; closing local UDP connection with error [{}]", 
                (error_code) ? std::to_string(*error_code).c_str() : "NONE");

        auto peer = client.peer();
        log::info(log_cat, "Closing connection to {}:{}", peer.ip.c_str(), peer.port);

        client.clear();
        client.close();
    }


    Handler::Handler(std::shared_ptr<uvw::Loop> loop_ptr, Network& net) : net{net}
    {
        ev_loop = loop_ptr;
        universal_handle = ev_loop->resource<uvw::UDPHandle>();

        universal_handle->bind(default_local);
        net.mapped_client_addrs.emplace(Address{default_local}, universal_handle);

        log::info(log_cat, "{}", (ev_loop) ? 
            "Event loop successfully created" : 
            "Error: event loop creation failed");
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
            ev_loop->clear();
            ev_loop->stop();
            ev_loop->close();
            log::debug(log_cat, "Event loop shut down...");
        }

        clients.clear();
        servers.clear();
    }


    std::shared_ptr<uvw::Loop>
    Handler::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }


    void
    Handler::client_call_async(async_callback_t async_cb)
    {
        for (const auto& itr : clients)
        {
            itr->client->call_async_all(async_cb);
        }
    }


    void
    Handler::client_close()
    {
        for (const auto& c : clients)
        {
            
        }
    }


    /*
    ConnectionID 
    Handler::make_client(std::shared_ptr<ClientManager> client_manager)
    {
       log::trace(log_cat, "Making client endpoint...");
        
        // create client endpoint inside client_manager object
        auto& client = client_manager->client;
        assert(not client);
        client = std::make_unique<Client>(*this);

        // create new connection, emplace into client->conns indexed by ID, retrieve {ID, conn_ptr}
        auto [conn_ID, conn_ptr] = client->make_conn(client_manager->remote, client_manager->local);

        // set conn_ptr inside 

        conn_ptr->on_stream_available = [&client_manager](Connection&)
        {
           log::trace(log_cat, "QUIC connection established; streams now available");
            
            if (client_manager->open_cb)
            {
               log::trace(log_cat, "Calling client tunnel open callback");
                client_manager->open_cb(true, nullptr);
                // only call once; always clear after calling
                client_manager->open_cb = nullptr;
            }
            else
               log::trace(log_cat, 
                    "Error: Connection::on_stream_available fired with no associated client tunnel object");
        };

        conn_ptr->on_closing = [&client_manager](Connection&)
        {
           log::trace(log_cat, "QUIC connection closing; shutting down tunnel");

            if (client_manager->close_cb)
            {
               log::trace(log_cat, "Calling client tunnel close callback");
                client_manager->close_cb(0, nullptr);
            }
            else
               log::trace(log_cat, 
                    "Error: Connection::on_closing fired with no associated client tunnel object");

            client_manager->udp_handle->close();
        };

       log::trace(log_cat, "Client endpoint successfully created");
        
        return ConnectionID::random();
    }
    

    void 
    Handler::make_server(std::string host, uint16_t port)
    {
       log::trace(log_cat, "Making server endpoint...");

        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();

        udp_handle->once<uvw::UDPDataEvent>([](const uvw::UDPDataEvent& event, uvw::UDPHandle& udp)
        {
           log::trace(log_cat, "Received data: %s", event.data.get());
           log::trace(log_cat, "Finished UDPDataEvent");
        });

        udp_handle->bind(host, port);
        udp_handle->recv();

        //ev_loop->run();

       log::trace(log_cat, "Server endpoint successfully created");
    }
    */
}   // namespace oxen::quic
