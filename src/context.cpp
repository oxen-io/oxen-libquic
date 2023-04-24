#include "context.hpp"
#include "handler.hpp"
#include "utils.hpp"

#include <uvw.hpp>

#include <stdexcept>
#include <memory>


namespace oxen::quic
{
    Context::Context(std::shared_ptr<uvw::Loop> loop_ptr)
    {
        fprintf(stderr, "Beginning context creation\n");
        quic_manager = std::make_unique<Handler>(loop_ptr);
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


    Handler*
    Context::get_quic()
    {
        return (quic_manager) ? quic_manager.get() : nullptr;
    }


    void
    Context::shutdown_test()
    {
        quic_manager->close(true);
        quic_manager.reset();
        fprintf(stderr, "Test framework shut down, tunnel manager deleted\n");
    }


    void
    Context::listen_to(std::string host, uint16_t port)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try
        {
            ep->listen(host, port);
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


    template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool>>
    void
    Context::udp_connect(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
        T cert, open_callback open_cb, close_callback close_cb)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        open_callback on_open = [open = std::move(open_cb)](bool success, void* user_data) 
        {
            fprintf(stderr, "QUIC tunnel opened %s\n", (success) ? "successfully" : "unsuccessfully");

            if (open)
                open(success, user_data);
        };

        close_callback on_close = [remote_host, remote_port,close = std::move(close_cb)](int rv, void* user_data)
        {
            fprintf(stderr, "QUIC tunnel closed to %s:%d\n", remote_host.c_str(), remote_port);

            if (close)
                close(rv, user_data);
        };

        try 
        {
            auto rv = ep->udp_connect_secured(
                local_host, local_port, remote_host, remote_port, std::move(cert), std::move(on_open), std::move(on_close));
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
    Context::udp_connect(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
        open_callback open_cb, close_callback close_cb)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        open_callback on_open = [open = std::move(open_cb)](bool success, void* user_data) 
        {
            fprintf(stderr, "QUIC tunnel opened %s\n", (success) ? "successfully" : "unsuccessfully");

            if (open)
                open(success, user_data);
        };

        close_callback on_close = [remote_host, remote_port,close = std::move(close_cb)](int rv, void* user_data)
        {
            fprintf(stderr, "QUIC tunnel closed to %s:%d\n", remote_host.c_str(), remote_port);

            if (close)
                close(rv, user_data);
        };

        try 
        {
            auto rv = ep->udp_connect_unsecured(
                local_host, local_port, remote_host, remote_port, std::move(on_open), std::move(on_close));
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

    //  May be unneeded
    int 
    Context::configure_tunnel(Handler* handler) 
    {
        return 0;
    }


    /****** TEST FUNCTIONS ******/

    void
    Context::listen_test(std::string host, uint16_t port)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try
        {
            ep->echo_server_test(host, port);
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
    Context::send_oneshot_test(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, std::string msg)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try 
        {
            auto rv = ep->connect_oneshot_test(
                local_host, local_port, remote_host, remote_port, msg);
        }
        catch (std::exception& e)
        {
            fprintf(stderr, "Exception: %s\n", e.what());
        }
        catch (int err)
        {
            fprintf(stderr, "Error: opening QUIC tunnel [code: %d]", err);
        }
    }


    void
    Context::listen_nullcert_test(std::string host, uint16_t port, TLSCert cert)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try
        {
            ep->echo_server_test(host, port);
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
    Context::send_oneshot_nullcert_test(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
        TLSCert cert, std::string msg)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try 
        {
            auto rv = ep->connect_oneshot_test(
                local_host, local_port, remote_host, remote_port, msg);
        }
        catch (std::exception& e)
        {
            fprintf(stderr, "Exception: %s\n", e.what());
        }
        catch (int err)
        {
            fprintf(stderr, "Error: opening QUIC tunnel [code: %d]", err);
        }
    }

    /****************************/
}   // namespace oxen::quic
