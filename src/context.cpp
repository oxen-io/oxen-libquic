#include "context.hpp"
#include "tunnel.hpp"
#include "utils.hpp"

#include <stdexcept>
#include <uv.h>
#include <uvw/tcp.h>
#include <memory>


namespace oxen::quic
{
    Context::Context()
    {
        fprintf(stderr, "Beginning context creation\n");
        quic_manager = std::make_unique<Tunnel>(*this);
        init();
    }


    Context::~Context()
    {
        fprintf(stderr, "Shutting down context...\n");
    }


    void
    Context::init()
    {
        fprintf(stderr, "Configuring tunnel endpoint\n");
        
        // configure tunnel object
        if (auto rv = configure_tunnel(quic_manager.get()); rv != 0)
            throw std::runtime_error{"Tunnel manager not configured correctly"};
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
            ep->listen(port);
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

        open_callback on_open = [laddr = std::move(local_addr), remote_host, remote_port, 
            open = std::move(open_cb)](bool success, void* user_data) 
        {
            fprintf(stderr, "QUIC tunnel opened %s\n", (success) ? "successfully" : "unsuccessfully");

            if (open)
                open(success, user_data);
        };

        close_callback on_close = [laddr = std::move(local_addr), remote_host, remote_port, 
            close = std::move(close_cb)](int rv, void* user_data)
        {
            fprintf(stderr, "QUIC tunnel closed to %s:%d\n", remote_host.c_str(), remote_port);

            if (close)
                close(rv, user_data);
        };

        try 
        {
            auto rv = ep->open(
                remote_host, remote_port, std::move(on_open), std::move(on_close), local_addr);
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
