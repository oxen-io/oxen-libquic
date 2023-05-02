#include "handler.hpp"
#include "context.hpp"
#include "network.hpp"
#include "crypto.hpp"
#include "server.hpp"
#include "client.hpp"
#include "endpoint.hpp"
#include "connection.hpp"
#include "utils.hpp"

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
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>


namespace oxen::quic
{
    // Takes data from the tcp connection and pushes it down the quic tunnel
    void
    on_outgoing_data(uvw::DataEvent& event, uvw::TCPHandle& client)
    {
        auto stream = client.data<Stream>();
        assert(stream);
        std::string data{event.data.get(), event.length};
        auto peer = client.peer();

        fprintf(stderr, "%s:%u → %s", peer.ip.c_str(), peer.port, data.c_str());
        // Steal the buffer from the DataEvent's unique_ptr<char[]>
        stream->append_buffer(reinterpret_cast<const std::byte*>(event.data.release()), event.length);
        if (stream->used() >= PAUSE_SIZE)
        {
            fprintf(stderr, "QUIC tunnel is congested (have %lu bytes in flight); pausing local tcp connection reading\n",
                stream->used());
            client.stop();
            stream->when_available([](Stream& s) {
                auto client = s.get_user_data<uvw::TCPHandle>();
                if (s.used() < PAUSE_SIZE)
                {
                    fprintf(stderr, "QUIC tunnel is no longer congested; resuming tcp connection reading\n");
                    client->read();
                    return true;
                }
                return false;
            });
        }
        else
        {
            fprintf(stderr, "Queued %lu bytes", event.length);
        }
    }


    // Received data from the quic tunnel and sends it to the TCP connection
    void
    on_incoming_data(Stream& stream, bstring bdata)
    {
      auto tcp = stream.get_user_data<uvw::TCPHandle>();
      if (!tcp)
        return;  // TCP connection is gone, which would have already sent a stream close, so just
                 // drop it.

      std::string data{reinterpret_cast<const char*>(bdata.data()), bdata.size()};
      auto peer = tcp->peer();
      fprintf(stderr, "%s:%u ← lokinet %s\n", peer.ip.c_str(), peer.port, data.c_str());

      if (data.empty())
        return;

      // Try first to write immediately from the existing buffer to avoid needing an
      // allocation and copy:
      auto written = tcp->tryWrite(const_cast<char*>(data.data()), data.size());
      if (written < (int)data.size())
      {
        data.erase(0, written);

        auto wdata = std::make_unique<char[]>(data.size());
        std::copy(data.begin(), data.end(), wdata.get());
        tcp->write(std::move(wdata), data.size());
      }
    }


    void
    close_tcp_pair(Stream& st, std::optional<uint64_t>)
    {
        if (auto tcp = st.get_user_data<uvw::UDPHandle>())
        {
            fprintf(stderr, "Closing TCP connection");
            tcp->close();
        }
    };


    void
    install_stream_forwarding(uvw::TCPHandle& tcp, Stream& stream)
    {
        tcp.data(stream.shared_from_this());
        auto weak_conn = stream.get_conn().weak_from_this();

        tcp.clear();  // Clear any existing initial event handlers

        tcp.on<uvw::CloseEvent>([weak_conn = std::move(weak_conn)](auto&, uvw::TCPHandle& c) 
        {
            // This fires sometime after we call `close()` to signal that the close is done.
            if (auto stream = c.data<Stream>())
            {
                fprintf(stderr, "Local TCP connection closed, closing associated quic stream %lu", stream->stream_id);

                // There is an awkwardness with Stream ownership, so make sure the Connection
                // which it holds a reference to still exists, as stream->close will segfault
                // otherwise
                if (auto locked_conn = weak_conn.lock())
                    stream->close(-1);
                stream->set_user_data(nullptr);
            }
            c.data(nullptr);
        });
        tcp.on<uvw::EndEvent>([](auto&, uvw::TCPHandle& c) {
            // This fires on eof, most likely because the other side of the TCP connection closed it.
            fprintf(stderr, "Error: EOF on connection to %s:%u\n", c.peer().ip.c_str(), c.peer().port);
            c.close();
        });
        tcp.on<uvw::ErrorEvent>([](const uvw::ErrorEvent& e, uvw::TCPHandle& tcp) {
            fprintf(stderr, "ErrorEvent[%s:%s] on connection with %s:%u, shutting down quic stream\n",
                e.name(),
                e.what(),
                tcp.peer().ip.c_str(),
                tcp.peer().port);

            if (auto stream = tcp.data<Stream>())
            {
                stream->close(ERROR_TCP);
                stream->set_user_data(nullptr);
                tcp.data(nullptr);
            }
        });
        tcp.on<uvw::DataEvent>(on_outgoing_data);
        stream.data_callback = on_incoming_data;
        stream.close_callback = close_tcp_pair;
    }


    void
    initial_client_data_handler(uvw::TCPHandle& client, Stream& stream, bstring data)
    {
        if (data.empty())
            return;
        client.clear();
        if (auto b0 = data[0]; b0 == CONNECT_INIT)
        {
            client.read();
            install_stream_forwarding(client, stream);

            if (data.size() > 1)
            {
                data.erase(0, 1);
                stream.data_callback(stream, data);
            }
        }
        else
        {
            fprintf(stderr, "Error: remote connection returned invalid initial byte; dropping\n");
            stream.close(ERROR_BAD_INIT);
            client.close();
        }

        stream.io_ready();
    }


    void
    initial_client_close_handler(uvw::TCPHandle& client, Stream& stream, std::optional<uint64_t> error_code)
    {
        if (error_code && *error_code == ERROR_CONNECT)
            fprintf(stderr, "Error: Remote TCP connection failed, closing local connection\n");
        else
            fprintf(stderr, "Stream connection closed; closing local TCP connection with error [%s]\n", 
                (error_code) ? std::to_string(*error_code).c_str() : "NONE");

        auto peer = client.peer();
        fprintf(stderr, "Closing connection to %s:%u\n", peer.ip.c_str(), peer.port);

        client.clear();
        client.close();
    }


    Handler::Handler(std::shared_ptr<uvw::Loop> loop_ptr)
    {
        ev_loop = loop_ptr;
        
        fprintf(stderr, "%s\n", (ev_loop) ? 
            "Event loop successfully created" : 
            "Error: event loop creation failed");
    }


    Handler::~Handler()
    {
        fprintf(stderr, "Shutting down tunnel manager...\n");
        close(true);
        fprintf(stderr, "Event loop shut down...\n");
    }


    std::shared_ptr<uvw::Loop>
    Handler::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }
    

    void
    Handler::send_datagram(std::shared_ptr<uvw::UDPHandle> handle, Address& destination, char* data, size_t datalen)
    {
        handle->send(destination, data, datalen);
    }


    void
    Handler::send_datagram(std::shared_ptr<uvw::UDPHandle> handle, Address& destination, std::string data)
    {
        handle->send(destination, &data[0], data.length());
    }


    void
	Handler::receive_packet(Address remote, const bstring& buf)
    {
        if (buf.size() <= 4)
        {
            fprintf(stderr, "Invalid QUIC packet: packet size too small\n");
            return;
        }

        std::byte type = buf[0];
        auto ecn = static_cast<uint8_t>(buf[3]);
        uint16_t remote_port_n, remote_port;
        std::memcpy(&remote_port_n, &buf[1], 2);
        remote_port = ntohs(remote_port_n);
        Endpoint* ep = nullptr;
        
        if (type == CLIENT_TO_SERVER)
        {
            fprintf(stderr, "Packet is client->server\n");
            if (!server_ptr)
            {
                fprintf(stderr, "Error: no listeners for incoming client -> server QUIC packet; dropping packet\n");
                return;
            }
            ep = server_ptr.get();
        }
        else if (type == SERVER_TO_CLIENT)
        {
            fprintf(stderr, "Packet is server->client\n");
            //ep = client_tunnel->client.get();

            if (!ep)
            {
                fprintf(stderr, "Error: incoming QUIC packet addressed to invalid/closed client; dropping packet\n");
                return;
            }
            
            /*if (auto conn = ep->get_conn())
            {
                assert(remote_port == conn->path.remote.port());
                fprintf(stderr, "Remote port is %hu\n", remote_port);
            }
            else
            {
                fprintf(stderr, "Invalid QUIC packet type; dropping packet\n");
                return;
            }*/
        }
        else
        {
            fprintf(stderr, "Invalid incoming QUIC packet type; dropping packet\n");
            return;
        }

        //Packet pkt{
        //    Path{Address{reinterpret_cast<const sockaddr_in&>(in6addr_loopback), remote_port}, 
        //        std::move(remote_addr)},
        //    buf,
        //    ngtcp2_pkt_info{.ecn=ecn}
        //};

        //ep->handle_packet(pkt);
    };


    void
    Handler::close(bool all)
    {
        for (auto& itr : clients)
        {
            itr.second->udp_handles->udp_handle->close();
            itr.second->udp_handle->data(nullptr);
            itr.second.reset();
        }

        if (all and ev_loop)
        {
            ev_loop->clear();
            ev_loop->stop();
            ev_loop->close();
        }

        fprintf(stderr, "TCP handles closed...\n");
    }


    void
    Handler::listen(std::string host, uint16_t port)
    {
        make_server(host, port);
    }


    int
    Handler::udp_connect(Address& local, Address& remote, open_callback on_open, close_callback on_close)
    {
        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();

        udp_handle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent& event, uvw::UDPHandle& handle)
        {
            handle.close();
            throw std::runtime_error{event.what()};
        });

        udp_handle->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Successfully connected to port:%u\n", udp.sock().port);
        });

        udp_handle->once<uvw::SendEvent>([](const uvw::SendEvent& event, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Finished SendEvent\n");
        });

        udp_handle->connect(remote);

        // create client manager object and set addresses/cbacks
        auto client_manager = std::make_shared<ClientManager>();
        client_manager->open_cb = std::move(on_open);
        client_manager->close_cb = std::move(on_close);
        client_manager->set_addrs(local, remote);

        // emplace shared ptr inside client manager set
        client_manager->udp_handles.emplace(udp_handle);

        // make client object
        auto ID = make_client(client_manager);

        // emplace client manager in handler map
        clients.emplace(remote.string_addr, client_manager);

        return 0;
    }


    template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool>>
    int
    Handler::udp_connect(Address& local, Address& remote, T cert, open_callback on_open, close_callback on_close)
    {
        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();

        udp_handle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent& event, uvw::UDPHandle& handle)
        {
            handle.close();
            throw std::runtime_error{event.what()};
        });

        udp_handle->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Successfully connected to port:%u\n", udp.sock().port);
        });

        udp_handle->once<uvw::SendEvent>([](const uvw::SendEvent& event, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Finished SendEvent\n");
        });

        udp_handle->connect(remote);

        // create client manager object and set addresses/cbacks/certs
        auto client_manager = std::make_shared<ClientManager>();
        client_manager->open_cb = std::move(on_open);
        client_manager->close_cb = std::move(on_close);
        client_manager->set_addrs(local, remote);

        // emplace shared ptr inside client manager set
        client_manager->udp_handles.emplace(udp_handle);

        // make client object
        auto ID = make_client(client_manager);

        // emplace unique_ptr to cert for cert_manager
        auto tls_context = std::move(cert).into_context();

        // emplace cert manager into client manager indexed by ID
        client_manager->cert_managers.emplace(ID, std::move(tls_context));

        // emplace client manager in handler map
        clients.emplace(remote.string_addr, client_manager);

        return 0;
    }


    ConnectionID 
    Handler::make_client(std::shared_ptr<ClientManager> client_manager)
    {
        fprintf(stderr, "Making client endpoint...\n");

        // create client endpoint inside client_manager object
        auto& client = client_manager->client;
        assert(not client);
        client = std::make_unique<Client>(*this);

        // create new connection, emplace into client->conns indexed by ID, retrieve {ID, conn_ptr}
        auto [conn_ID, conn_ptr] = client->make_conn(client_manager->remote, client_manager->local);

        // set conn_ptr inside 

        conn_ptr->on_stream_available = [&client_manager](Connection&)
        {
            fprintf(stderr, "QUIC connection established; streams now available\n");
            
            if (client_manager->open_cb)
            {
                fprintf(stderr, "Calling client tunnel open callback\n");
                client_manager->open_cb(true, nullptr);
                // only call once; always clear after calling
                client_manager->open_cb = nullptr;
            }
            else
                fprintf(stderr, 
                    "Error: Connection::on_stream_available fired with no associated client tunnel object\n");
        };

        conn_ptr->on_closing = [&client_manager](Connection&)
        {
            fprintf(stderr, "QUIC connection closing; shutting down tunnel\n");

            if (client_manager->close_cb)
            {
                fprintf(stderr, "Calling client tunnel close callback\n");
                client_manager->close_cb(0, nullptr);
            }
            else
                fprintf(stderr, 
                    "Error: Connection::on_closing fired with no associated client tunnel object\n");

            client_manager->udp_handle->close();
        };

        fprintf(stderr, "Client endpoint successfully created\n");

        return conn_ID;
    }


    void 
    Handler::make_server(std::string host, uint16_t port)
    {
        fprintf(stderr, "Making server endpoint...\n");

        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();

        udp_handle->once<uvw::UDPDataEvent>([](const uvw::UDPDataEvent& event, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Received data: %s\n", event.data.get());
            fprintf(stderr, "Finished UDPDataEvent\n");
        });

        udp_handle->bind(host, port);
        udp_handle->recv();

        //ev_loop->run();

        fprintf(stderr, "Server endpoint successfully created\n");
    }


    /****** TEST FUNCTIONS ******/
    
    void 
    Handler::echo_server_test(std::string host, uint16_t port)
    {
        fprintf(stderr, "Making server endpoint...\n");
        server_ptr = std::make_unique<Server>(*this);

        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();

        udp_handle->once<uvw::UDPDataEvent>([](const uvw::UDPDataEvent& event, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Received data: %s\n", event.data.get());
            fprintf(stderr, "Finished UDPDataEvent\n");
            udp.close();
        });

        udp_handle->bind(host, port);
        udp_handle->recv();

        fprintf(stderr, "Server endpoint successfully created\n");
    }

    int
    Handler::connect_oneshot_test(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, std::string message)
    {
        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();
        size_t msg_len = message.length();

        udp_handle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent& event, uvw::UDPHandle& handle)
        {
            handle.close();
            throw std::runtime_error{event.what()};
        });

        udp_handle->once<uvw::SendEvent>([](const uvw::SendEvent& event, uvw::UDPHandle& udp)
        {
            udp.close();
            fprintf(stderr, "Finished SendEvent\n");
        });

        fprintf(stderr, "Sending message via UDP...\n");
        udp_handle->send(remote_host, remote_port, &message[0], msg_len);
        return 0;
    }

    void
    Handler::echo_server_nullcert_test(std::string host, uint16_t port, TLSCert cert)
    {
        fprintf(stderr, "Making server endpoint...\n");
        server_ptr = std::make_unique<Server>(*this);

        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();

        udp_handle->once<uvw::UDPDataEvent>([](const uvw::UDPDataEvent& event, uvw::UDPHandle& udp)
        {
            fprintf(stderr, "Received data: %s\n", event.data.get());
            fprintf(stderr, "Finished UDPDataEvent\n");
            udp.close();
        });

        udp_handle->bind(host, port);
        udp_handle->recv();

        fprintf(stderr, "Server endpoint successfully created\n");
    }

    int
    Handler::connect_oneshot_nullcert_test(
        std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, TLSCert cert, std::string message)
    {
        auto udp_handle = ev_loop->resource<uvw::UDPHandle>();
        size_t msg_len = message.length();

        udp_handle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent& event, uvw::UDPHandle& handle)
        {
            handle.close();
            throw std::runtime_error{event.what()};
        });

        udp_handle->once<uvw::SendEvent>([](const uvw::SendEvent& event, uvw::UDPHandle& udp)
        {
            udp.close();
            fprintf(stderr, "Finished SendEvent\n");
        });

        fprintf(stderr, "Sending message via UDP...\n");
        udp_handle->send(remote_host, remote_port, &message[0], msg_len);
        return 0;
    }

    /****************************/
    
}   // namespace oxen::quic
