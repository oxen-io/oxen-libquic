#include "tunnel.hpp"
#include "context.hpp"
#include "server.hpp"
#include "client.hpp"
#include "endpoint.hpp"
#include "connection.hpp"
#include "utils.hpp"
#include "uvw/tcp.h"

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
                auto client = s.data<uvw::TCPHandle>();
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
      auto tcp = stream.data<uvw::TCPHandle>();
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
        if (auto tcp = st.data<uvw::TCPHandle>())
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
                stream->data(nullptr);
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
                stream->data(nullptr);
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


    ClientTunnel::~ClientTunnel()
    {
        if (tcp_socket)
        {
            tcp_socket->close();
            tcp_socket->data(nullptr);
            tcp_socket.reset();
        }
        for (auto& conn: conns)
            conn->close();
        conns.clear();
    }


    Tunnel::Tunnel(Context& ctx)
    {
        ev_loop = uvw::Loop::create();

        fprintf(stderr, "%s\n", (ev_loop) ? 
            "Event loop successfully created" : 
            "Error: event loop creation failed");
    }


    Tunnel::~Tunnel()
    {
        fprintf(stderr, "Shutting down tunnel manager...\n");
        ev_loop->clear();
        ev_loop->stop();
        fprintf(stderr, "Event loop shut down...\n");
        close();
    }


    std::shared_ptr<uvw::Loop>
    Tunnel::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }


    io_result
    Tunnel::send_packet(const Address& destination, bstring data, uint8_t ecn, std::byte type)
    {
        struct iovec iov = {reinterpret_cast<char*>(data.data()), data.length()};
        struct msghdr msg = {0};
        ssize_t nwrite;

        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        do {
            nwrite = sendmsg(tun_fd, &msg, 0);
        } while (nwrite == -1 && errno == EINTR);

        if (nwrite == -1)
        {
            fprintf(stderr, "Error: call to sendmsg failed [code: %s]\n", strerror(errno));
            return io_result{-1};
        }

        return io_result{0};
    }


    void
    Tunnel::flush_incoming(ClientTunnel &ct)
    {
        if (!ct.client)
            return;
        
        auto& c = *ct.client->get_conn();

        if (not c)
            return;
        
        int available = c.get_streams_available();
        auto tcp = ct.tcp_socket;

        while (available > 0)
        {
            c.open_stream(
                [tcp](auto&&... args){
                    initial_client_data_handler(*tcp, std::forward<decltype(args)>(args)...);}, 
                [tcp](auto&&... args){
                    initial_client_close_handler(*tcp, std::forward<decltype(args)>(args)...);}
            );
        }

    }


    void
	Tunnel::receive_packet(Address remote, const bstring& buf)
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
            ep = client_tunnel->client.get();

            if (!ep)
            {
                fprintf(stderr, "Error: incoming QUIC packet addressed to invalid/closed client; dropping packet\n");
                return;
            }
            
            if (auto conn = ep->get_conn())
            {
                assert(remote_port == conn->path.remote.port());
                fprintf(stderr, "Remote port is %hu\n", remote_port);
            }
            else
            {
                fprintf(stderr, "Invalid QUIC packet type; dropping packet\n");
                return;
            }
        }
        else
        {
            fprintf(stderr, "Invalid incoming QUIC packet type; dropping packet\n");
            return;
        }

        auto remote_addr = Address{REMOTE_HOST, remote_port};

        Packet pkt{
            Path{Address{reinterpret_cast<const sockaddr_in&>(in6addr_loopback), remote_port}, 
                std::move(remote_addr)},
            buf,
            ngtcp2_pkt_info{.ecn=ecn}
        };

        ep->handle_packet(pkt);
    };


    void
    Tunnel::close()
    {
        auto tcp_sock = client_tunnel->tcp_socket;
        if (tcp_sock)
        {
            tcp_sock->close();
            tcp_sock->data(nullptr);
            tcp_sock.reset();

            fprintf(stderr, "TCP handle closed...\n");
        }
    }


    void
    Tunnel::listen(uint16_t port)
    {
        if (!server_cb)
            server_cb = [p = port](uint16_t port) { return Address{"127.0.0.1", (port) ? port : p}; };
        if (!server_ptr)
            make_server();
    }


    int
    Tunnel::open(std::string remote_address, uint16_t remote_port, open_callback on_open, close_callback on_close, Address& bind_addr)
    {
        std::string _remote_address = str_tolower(remote_address);

        auto tcp_tunnel = loop()->resource<uvw::TCPHandle>();
        const char* failed = nullptr;

        auto err_handler = tcp_tunnel->once<uvw::ErrorEvent>([&failed](auto& event, auto&) { failed = event.what(); });

        tcp_tunnel->bind(bind_addr);

        tcp_tunnel->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& tcp_tunnel) {
            auto client_handle = tcp_tunnel.loop().resource<uvw::TCPHandle>();
            tcp_tunnel.accept(*client_handle);
            client_handle->stop();

            auto p = tcp_tunnel.data<uint16_t>();

            if (client_tunnel->tcp_socket->data<uint16_t>() == p)
            {
                flush_incoming(*client_tunnel);
                return;
            }

            tcp_tunnel.data(nullptr);
            client_handle->close();
        });
        tcp_tunnel->listen();
        tcp_tunnel->erase(err_handler);

        if (failed)
        {
            std::cout << failed << std::endl;
            tcp_tunnel->close();
            throw std::runtime_error("Failed to bind local TCP tunnel socket");
        }
        
        auto bound = tcp_tunnel->sock();
        std::cout << "Bound local TCP tunnel socket (host order) " << bound.ip << ":" << bound.port << std::endl;
        auto source_addr = Address{bound.ip, static_cast<uint16_t>(bound.port)};
        auto remote_addr = Address{_remote_address, remote_port};

        // emplace new connection into client tunnel
        client_tunnel = std::make_unique<ClientTunnel>();
        client_tunnel->open_cb = std::move(on_open);
        client_tunnel->close_cb = std::move(on_close);
        client_tunnel->tcp_socket = std::move(tcp_tunnel);

        make_client(remote_port, remote_addr);
        
        return 0;
    }


    void 
    Tunnel::make_client(
        const uint16_t remote_port, Address& remote)
    {
        fprintf(stderr, "Making client endpoint...\n");
        assert(remote.port() > 0);
        auto& ctun_c = client_tunnel->client;
        assert(not ctun_c);
        ctun_c = std::make_unique<Client>(*this, remote.port(), std::move(remote));
        auto client_conn = ctun_c->get_conn();

        client_conn->on_stream_available = [this](Connection&) 
        {
            fprintf(stderr, "QUIC connection established; streams now available\n");

            flush_incoming(*client_tunnel);
            
            if (client_tunnel->open_cb)
            {
                fprintf(stderr, "Calling client tunnel open callback\n");
                client_tunnel->open_cb(true, nullptr);
                // only call once; always clear after calling
                client_tunnel->open_cb = nullptr;
            }
            else
                fprintf(stderr, 
                    "Error: Connection::on_stream_available fired with no associated client tunnel object\n");
        };

        client_conn->on_closing = [this](Connection&)
        {
            fprintf(stderr, "QUIC connection closing; shutting down tunnel\n");

            auto client_handle = client_tunnel->tcp_socket;
            auto client_conn = client_tunnel->client->get_conn();

            if (client_tunnel->close_cb)
            {
                fprintf(stderr, "Calling client tunnel close callback\n");
                client_tunnel->close_cb(0, nullptr);
            }
            else
                fprintf(stderr, 
                    "Error: Connection::on_closing fired with no associated client tunnel object\n");

            this->close();
        };

        fprintf(stderr, "Client endpoint successfully created\n");
        return;
    }


    void 
    Tunnel::make_server()
    {
        fprintf(stderr, "Making server endpoint...\n");
        server_ptr = std::make_unique<Server>(*this);
        server_ptr->stream_open_callback = [this](Stream& stream, uint16_t port) -> bool
        {
            stream.close_callback = close_tcp_pair;
            auto& conn = stream.get_conn();
            auto remote_addr = server_cb(port);

            if(conn.path.remote != remote_addr)
            {
                fprintf(stderr, "Error: incoming connection did not match stream address\n");
                return false;
            }

            if (not remote_addr) 
            {
                fprintf(stderr, "Error: remote address not resolved from incoming connection\n");
                return false;
            }

            auto tcp_handle = loop()->resource<uvw::TCPHandle>();

            auto error_handler = tcp_handle->once<uvw::ErrorEvent>([&stream](const uvw::ErrorEvent&, uvw::TCPHandle&)
            {
                fprintf(stderr, "Eror: Failed to connect to remote; shutting down QUIC stream\n");
                stream.close(ERROR_CONNECT);
            });

            tcp_handle->once<uvw::ConnectEvent>(
                [stream_wptr = stream.weak_from_this(), error_handler = std::move(error_handler)](
                    const uvw::ConnectEvent&, uvw::TCPHandle& tcp_handle) 
                    {
                        auto peer = tcp_handle.peer();
                        auto stream = stream_wptr.lock();
                        if (!stream)
                        {
                            fprintf(stderr, 
                                "Error: Connected to TCP peer [%s:%i], but QUIC stream is gone; closing local TCP connection\n", 
                                peer.ip.c_str(), peer.port);
                            
                            tcp_handle.close();
                            return;
                        }
                        fprintf(stderr, 
                            "Connected to TCP peer [%s:%i] for QUIC stream ID: %li\n", 
                            peer.ip.c_str(), peer.port, stream->stream_id);
                        // set up stream forwarding
                        install_stream_forwarding(tcp_handle, *stream);
                        // send magic byte, start reading from tcp_tunnel
                        stream->append_buffer(new std::byte[1]{CONNECT_INIT}, 1);
                        tcp_handle.read();
                    });

            fprintf(stderr, "TCP handle attempting to create stream to port %hu\n", remote_addr.port());
            tcp_handle->connect(remote_addr.operator const sockaddr&());
            fprintf(stderr, "Stream created\n");
            return true;
        };

        fprintf(stderr, "Server endpoint successfully created\n");
        return;
    }
    
}   // namespace oxen::quic
