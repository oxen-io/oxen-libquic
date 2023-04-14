#include "tunnel.hpp"
#include "context.hpp"
#include "server.hpp"
#include "client.hpp"
#include "endpoint.hpp"
#include "connection.hpp"
#include "utils.hpp"

#include <uvw/emitter.h>
#include <uvw/stream.h>
#include <uvw/tcp.h>

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
        ev_loop = std::make_shared<uvw::Loop>(ctx.ev_loop);
    }


    Tunnel::~Tunnel()
    {
        ev_loop->clear();
        ev_loop->stop();
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

        auto remote_addr = Address{reinterpret_cast<const sockaddr_in6&>(in6addr_loopback), remote_port};

        Packet pkt{
            Path{Address{reinterpret_cast<const sockaddr_in6&>(in6addr_loopback), remote_port}, 
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
        tcp_sock->close();
        tcp_sock->data(nullptr);
        tcp_sock.reset();
    }


    void
    Tunnel::listen()
    {
        if (!server_cb)
            server_cb = [](std::string addr, uint16_t port) { return Address{"127.0.0.1", port}; };
        if (!server_ptr)
            make_server();
    }



    int
    Tunnel::open(std::string remote_address, uint16_t remote_port, open_callback on_open, close_callback on_close, Address bind_addr)
    {
        std::string _remote_address = str_tolower(remote_address);
        Address ra{};

        auto tcp_tunnel = loop()->resource<uvw::TCPHandle>();
        const char* failed = nullptr;

        auto err_handler = tcp_tunnel->once<uvw::ErrorEvent>([&failed](auto& event, auto&) {
            failed = event.what(); });
        tcp_tunnel->bind(*bind_addr.operator const sockaddr*());
        tcp_tunnel->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& tcp_tunnel) {
            auto client_handle = tcp_tunnel.loop().resource<uvw::TCPHandle>();
            tcp_tunnel.accept(*client_handle);
            client_handle->stop();
            auto client_conn = client_tunnel->client->get_conn();
            client_conn->open_stream(
                [client_handle](Stream& s, bstring data)
                {
                    if (data.empty())
                        return;
                    if (auto b0 = data[0]; b0 == CONNECT_INIT)
                    {
                        client_handle->read();
                        if (data.size() > 1)
                        {
                            data.erase(0, 1);
                            s.data_callback(s, data);
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Error: remote connection returned invalid initial byte; dropping\n");
                        s.close(ERROR_BAD_INIT);
                        client_handle->close();
                    }
                }, 
                [client_handle](Stream& s, uint64_t code)
                {
                    if (code && code == ERROR_CONNECT)
                        fprintf(stderr, "Error: remote TCP connection failed; closing local connection\n");
                    else
                        fprintf(stderr, "Stream connection closed [code: %s]; closing local connection\n", (code) ? 
                            strerror(code) : 
                            "NONE");
                    
                    auto peer = client_handle->peer();
                    fprintf(stderr, "Closing connection to TPC peer [%s:%i]\n", peer.ip.c_str(), peer.port);
                    client_handle->clear();
                    client_handle->close();
                    
                }
            );
            client_conn->io_ready();
            client_handle->close();
        });
        tcp_tunnel->listen();
        tcp_tunnel->erase(err_handler);

        if (failed)
        {
            tcp_tunnel->close();
            throw std::runtime_error("Failed to bind local TCP tunnel socket");
        }

        auto bound = tcp_tunnel->sock();
        auto source_addr = Address{bound.ip, static_cast<uint16_t>(bound.port)};
        auto remote_addr = Address{_remote_address, remote_port};

        // emplace new connection into client tunnel
        client_tunnel->open_cb = std::move(on_open);
        client_tunnel->close_cb = std::move(on_close);
        client_tunnel->tcp_socket = std::move(tcp_tunnel);
        //client_tunnel->tcp_socket->data(std::make_shared<uint16_t>(pseudo_port));

        make_client(remote_port, remote_addr);
        
        return 0;
    }


    void
    Tunnel::reset_tcp_handles(uvw::TCPHandle& tcp, Stream& stream)
    {
        
        
    }


    void 
    Tunnel::make_client(
        const uint16_t remote_port, Address& remote)
    {
        assert(remote.port() > 0);
        assert(not client_tunnel->client);
        client_tunnel->client = std::make_unique<Client>(*this, remote.port(), std::move(remote));
        auto client_conn = client_tunnel->client->get_conn();

        client_conn->on_stream_available = [this](Connection&) 
        {
            fprintf(stderr, "QUIC connection established; streams now available\n");

            auto client_handle = client_tunnel->tcp_socket;
            auto client_conn = client_tunnel->client->get_conn();

            client_conn->open_stream(
                [client_handle](Stream& s, bstring data)
                {
                    if (data.empty())
                        return;
                    if (auto b0 = data[0]; b0 == CONNECT_INIT)
                    {
                        client_handle->read();
                        if (data.size() > 1)
                        {
                            data.erase(0, 1);
                            s.data_callback(s, data);
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Error: remote connection returned invalid initial byte; dropping\n");
                        s.close(ERROR_BAD_INIT);
                        client_handle->close();
                    }
                }, 
                [client_handle](Stream& s, uint64_t code)
                {
                    if (code && code == ERROR_CONNECT)
                        fprintf(stderr, "Error: remote TCP connection failed; closing local connection\n");
                    else
                        fprintf(stderr, "Stream connection closed [code: %s]; closing local connection\n", (code) ? 
                            strerror(code) : 
                            "NONE");
                    
                    auto peer = client_handle->peer();
                    fprintf(stderr, "Closing connection to TPC peer [%s:%i]\n", peer.ip.c_str(), peer.port);
                    client_handle->clear();
                    client_handle->close();
                    
                }
            );
            
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

            client_conn->open_stream(
                [client_handle](Stream& s, bstring data)
                {
                    if (data.empty())
                        return;
                    if (auto b0 = data[0]; b0 == CONNECT_INIT)
                    {
                        client_handle->read();
                        if (data.size() > 1)
                        {
                            data.erase(0, 1);
                            s.data_callback(s, data);
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Error: remote connection returned invalid initial byte; dropping\n");
                        s.close(ERROR_BAD_INIT);
                        client_handle->close();
                    }
                }, 
                [client_handle](Stream& s, uint64_t code)
                {
                    if (code && code == ERROR_CONNECT)
                        fprintf(stderr, "Error: remote TCP connection failed; closing local connection\n");
                    else
                        fprintf(stderr, "Stream connection closed [code: %s]; closing local connection\n", (code) ? 
                            strerror(code) : 
                            "NONE");
                    
                    auto peer = client_handle->peer();
                    fprintf(stderr, "Closing connection to TPC peer [%s:%i]\n", peer.ip.c_str(), peer.port);
                    client_handle->clear();
                    client_handle->close();
                    
                }
            );

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

        return;
    }


    void 
    Tunnel::make_server()
    {
        server_ptr = std::make_unique<Server>(*this);
        server_ptr->stream_open_callback = [this](Stream& stream, uint16_t port) -> bool
        {
            auto& conn = stream.get_conn();
            auto remote_addr = conn.path.remote;
            if (not remote_addr)
                return false;
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

                        // send magic byte, start reading from tcp_tunnel
                        stream->append_buffer(new std::byte[1]{CONNECT_INIT}, 1);
                        tcp_handle.read();
                    });

            tcp_handle->connect(remote_addr);

            return true;
        };

        return;
    }


    void
    Tunnel::close_connection(Connection& conn, int code, std::string_view msg)
    {
        fprintf(stderr, "Closing connection (CID: %s)\n", conn.source_cid.data);

        if (!conn || conn.closing || conn.draining)
            return;
        
        if (code == NGTCP2_ERR_IDLE_CLOSE)
        {
            fprintf(stderr, 
                "Connection (CID: %s) passed idle expiry timer; closing now without close packet\n", 
                conn.source_cid.data);
            delete_connection(conn.source_cid);
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (code == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            fprintf(stderr, 
            "Connection (CID: %s) passed idle expiry timer; closing now with close packet\n", 
            conn.source_cid.data);
        }

        ngtcp2_connection_close_error err;
        ngtcp2_connection_close_error_set_transport_error_liberr(
            &err, 
            code, 
            reinterpret_cast<uint8_t*>(const_cast<char*>(msg.data())), 
            msg.size());
        
        conn.conn_buffer.resize(max_pkt_size_v4);
        Path path;
        ngtcp2_pkt_info pkt_info;

        auto written = ngtcp2_conn_write_connection_close(
            conn, path, &pkt_info, u8data(conn.conn_buffer), conn.conn_buffer.size(), &err, get_timestamp());

        if (written <= 0)
        {
            fprintf(stderr, "Error: Failed to write connection close packet: ");
            fprintf(stderr, "[%s]\n", (written < 0) ? 
                strerror(written) : 
                "[Error Unknown: closing pkt is 0 bytes?]");
            
            delete_connection(conn.source_cid);
            return;
        }
        // ensure we have enough write space
        assert(written <= (long)conn.conn_buffer.size());

        if (auto rv = send_packet(conn.path.remote, conn.conn_buffer, 0, conn.pkt_type); not rv)
        {
            fprintf(stderr, 
                "Error: failed to send close packet [code: %s]; removing connection (CID: %s)\n", 
                strerror(rv.error_code), conn.source_cid.data);
            delete_connection(conn.source_cid);
        }
    }
    

    //  Opens TUN device and assigns it to ip_tunnel_t struct. The TUN 
    //  device is created using the name 'dev' (ex: 'tun0', 'tun1', etc),
    //  and is given the fd of the ip_tunnel_t struct
    int ip_tunnel_open(Tunnel* tunnel, const char* dev) 
    {
        if (!tunnel || !dev)
            return -1;

        // initialize interface request
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

        int fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            return -1;

        if (auto rv = ioctl(fd, TUNSETIFF, (void*)&ifr); rv < 0) 
        {
            close(fd);
            return -1;
        }

        tunnel->tun_fd = fd;
        return 0;
    }


    //  Takes the TUN device associated iwth the ip_tunnel_t struct and
    //  closes it, setting the tun_fd back to -1 to indicate that the ip
    //  tunnel is not open
    int ip_tunnel_close(Tunnel* tunnel) 
    {
        if (!tunnel || tunnel->tun_fd < 0)
            return -1;

        close(tunnel->tun_fd);
        tunnel->tun_fd = -1;
        free(tunnel->read_buffer);
        tunnel->read_buffer = NULL;
        return 0;
    }


    //  Reads data from TUN device associated with ip_tunnel_t struct. Copies
    //  data into provided buffer, returning the number of bytes read on success
    //  and -1 on error.
    ssize_t ip_tunnel_read(Tunnel* tunnel, unsigned char* buffer, size_t buffer_size) 
    {
        if (!tunnel || tunnel->tun_fd < 0 || !buffer || buffer_size == 0)
            return -1;

        ssize_t nbytes = read(tunnel->tun_fd, tunnel->read_buffer, IP_TUNNEL_MAX_BUFFER_SIZE);
        if (nbytes < 0)
            return -1;

        std::memcpy(buffer, tunnel->read_buffer, (nbytes < buffer_size) ? nbytes : buffer_size);
        return nbytes;
    }


    //  Writes data to the TUN device associated with the ip_tunnel_t struct. 
    //  Returns the number of bytes written on success and -1 on error
    ssize_t ip_tunnel_write(Tunnel* tunnel, const unsigned char* buffer, size_t buffer_size) 
    {
        if (!tunnel || tunnel->tun_fd < 0 || !buffer || buffer_size == 0)
            return -1;

        ssize_t nbytes = write(tunnel->tun_fd, buffer, buffer_size);
        return nbytes;
    }
}   // namespace oxen::quic
