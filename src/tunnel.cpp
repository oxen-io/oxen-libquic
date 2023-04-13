#include "tunnel.hpp"
#include "server.hpp"
#include "client.hpp"
#include "endpoint.hpp"
#include "connection.hpp"


#include <fcntl.h>
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

        while (not pending.empty())
        {
            if (auto tcp = pending.front().lock())
            {
                tcp->clear();
                tcp->close();
            }
            pending.pop();
        }
    }

    std::shared_ptr<uvw::Loop>
    Tunnel::get_loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }

    void
    Tunnel::flush_pending_incoming(ClientTunnel& ct)
    {
        if (!ct.client)
            return;
        auto& conn = *ct.client->get_conn();
        if (not conn)
            return;

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
        uint16_t pseudo_port, remote_port;
        std::memcpy(&pseudo_port, &buf[1], 2);
        Endpoint* ep = nullptr;
        

        if (type == CLIENT_TO_SERVER)
        {
            fprintf(stderr, "Packet is client->server from client port %hu", pseudo_port);
            if (!server_ptr)
            {
                fprintf(stderr, "Error: no listeners for incoming client -> server QUIC packet; dropping packet\n");
                return;
            }
            ep = server_ptr.get();
        }
        else if (type == SERVER_TO_CLIENT)
        {
            fprintf(stderr, "Packet is server->client to client port %hu", pseudo_port);
            // search client tunnels to find header port
            if (auto itr = client_tunnels.find(pseudo_port); itr != client_tunnels.end())
                ep = itr->second.client.get();

            if (!ep)
            {
                fprintf(stderr, "Error: incoming QUIC packet addressed to invalid/closed client; dropping packet\n");
                return;
            }
            
            if (auto conn = static_cast<Client&>(*ep).get_conn())
            {
                remote_port = conn->path.remote.port();
                fprintf(stderr, "Remote port is %hu", remote_port);
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
            Path{Address{reinterpret_cast<const sockaddr_in6&>(in6addr_loopback), remote_port}, remote_addr},
            buf,
            ngtcp2_pkt_info{.ecn=ecn}
        };

        ep->handle_packet(pkt);
    };

    void
    Tunnel::close(uint16_t cid)
    {
        if (auto it = client_tunnels.find(cid); it != client_tunnels.end())
        {
            auto ts = it->second.tcp_socket;
            ts->close();
            ts->data(nullptr);
            ts.reset();
        }
    }


    std::pair<Address, uint16_t>
    Tunnel::open(std::string remote_address, uint16_t port, open_callback on_open, close_callback on_close, Address bind_addr)
    {
        std::string remote_addr = str_tolower(remote_address);

        std::pair<Address, uint16_t> result;
        auto& [source_addr, pseudo_port] = result;

        auto tcp_tunnel = get_loop()->resource<uvw::TCPHandle>();
        const char* failed = nullptr;

        auto err_handler = tcp_tunnel->once<uvw::ErrorEvent>([&failed](auto& event, auto&) {
            failed = event.what(); });
        tcp_tunnel->bind(*bind_addr.operator const sockaddr*());
        tcp_tunnel->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& tcp_tunnel) {
            auto client = tcp_tunnel.loop().resource<uvw::TCPHandle>();
            tcp_tunnel.accept(*client);
            // Freeze the connection (after accepting) because we may need to stall it until a stream
            // becomes available; flush_pending_incoming will unfreeze it
            client->stop();
            auto pport = tcp_tunnel.data<uint16_t>();
            if (pport)
            {
                if (auto it = client_tunnels.find(*pport); it != client_tunnels.end())
                {
                    it->second.pending.emplace(std::move(client));
                    flush_pending_incoming(it->second);
                    return;
                }
                tcp_tunnel.data(nullptr);
            }
            client->close();
        });
        tcp_tunnel->listen();
        tcp_tunnel->erase(err_handler);

        if (failed)
        {
            tcp_tunnel->close();
            throw std::runtime_error("Failed to bind local TCP tunnel socket");
        }

        auto bound = tcp_tunnel->sock();

        // TOFIX: finish this
    }


    int 
    Tunnel::make_client(
        const uint16_t port, Address& remote, std::pair<const uint16_t, ClientTunnel>& row)
    {


        return 0;
    }


    int 
    Tunnel::make_server()
    {
        //auto srv = std::make_unique<Server>();

        return 0;
    }


    //  Initializes ip_tunnel_t structure with default values.
    //  'tun_fd' is set to -1, indicating the tunnel is not yet open
    int ip_tunnel_init(Tunnel* tunnel) 
    {
        if (!tunnel)
            return -1;

        tunnel->tun_fd = -1;
        std::memset(&tunnel->remote_addr, 0, sizeof(struct sockaddr_in));
        tunnel->read_buffer = (unsigned char*)malloc(IP_TUNNEL_MAX_BUFFER_SIZE);
        if (!tunnel->read_buffer)
            return -1;
        std::memset(tunnel->read_buffer, 0, IP_TUNNEL_MAX_BUFFER_SIZE);
        return 0;
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
