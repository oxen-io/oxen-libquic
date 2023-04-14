#include "context.hpp"
#include "utils.hpp"

#include <uv.h>
#include <uvw/tcp.h>
#include <memory>


namespace oxen::quic
{
    Context::Context()
    {
        fprintf(stderr, "Beginning context creation\n");

        ev_loop = std::make_shared<uvw::Loop>(ev_loop_queue_size);

        fprintf(stderr, "%s\n", (ev_loop) ? 
            "Event loop successfully created" : 
            "Error: event loop creation failed");

        init();
    }


    Context::~Context()
    {
        //ev_loop->clear();
        //ev_loop->close();
    }


    void
    Context::init()
    {
        fprintf(stderr, "Initializing context and configuring tunnel endpoint\n");
        
        // make and configure tunnel object
        quic_manager = std::make_unique<Tunnel>(*this);
        configure_tunnel(quic_manager.get());
    }


    std::shared_ptr<uvw::Loop>
    Context::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }


    int
    Context::socket()
    {
        return _socket_id;
    }


    Tunnel*
    Context::get_quic()
    {
        return (quic_manager) ? quic_manager.get() : nullptr;
    }


    void
    Context::server_call(uint16_t port)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try 
        {
            ep->listen();
        }
        catch (std::exception& e)
        {
            fprintf(stderr, "Exception:%s\n", e.what());
        }
        catch (int err)
        {
            fprintf(stderr, "Error: opening QUIC tunnel [code: %d]", err);
        }
    }


    void
    Context::client_call(Address& local_addr, std::string remote_host, uint16_t remote_port, open_callback open_cb, close_callback close_cb)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try 
        {
            auto rv = ep->open(
                remote_host, remote_port, std::move(open_cb), std::move(close_cb), local_addr);
        }
        catch (std::exception& e)
        {
            fprintf(stderr, "Exception:%s\n", e.what());
        }
        catch (int err)
        {
            fprintf(stderr, "Error: opening QUIC tunnel [code: %d]", err);
        }
    }


    void
    Context::on_open(Address& local_addr, std::string remote_host, int remote_port, void* user_data, bool success, open_callback open_cb)
    {
        fprintf(stderr, "Quic tunnel opened successfully to %s:%d\n", remote_host.c_str(), remote_port);

        if (open_cb)
            open_cb(success, user_data);
    }


    void
    Context::on_close(Address& local_addr, std::string remote_host, int remote_port, void* user_data, int rv, close_callback close_cb)
    {
        fprintf(stderr, "Quic tunnel closed successfully to %s:%d\n", remote_host.c_str(), remote_port);

        if (close_cb)
            close_cb(rv, user_data);
    }


    //  Initializes ip_tunnel_t structure with default values.
    //  'tun_fd' is set to -1, indicating the tunnel is not yet open
    int 
    Context::configure_tunnel(Tunnel* tunnel) 
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


    int 
    Context::next_socket_id()
    {
        int id = ++_socket_id;
        // check overflow case
        if (id < 0)
        {
            _socket_id = 0;
            id = ++_socket_id;
        }

        return id;
    }

}   // namespace oxen::quic
