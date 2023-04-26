#include "network.hpp"
#include "context.hpp"
#include "handler.hpp"
#include "utils.hpp"

#include <uvw.hpp>

#include <stdexcept>
#include <memory>


namespace oxen::quic
{
    Network::Network(std::shared_ptr<uvw::Loop> loop_ptr)
    {
        fprintf(stderr, "Beginning context creation\n");
        ev_loop = (loop_ptr) ? loop_ptr : uvw::Loop::create();
        quic_manager = std::make_shared<Handler>(ev_loop);
        init();
    }


    Network::~Network()
    {
        fprintf(stderr, "Shutting down context...\n");
    }


    void
    Network::init()
    {
        fprintf(stderr, "Configuring tunnel endpoint\n");
        
        // configure tunnel object
        if (auto rv = configure_tunnel(quic_manager.get()); rv != 0)
            throw std::runtime_error{"Tunnel manager not configured correctly"};
    }


    Handler*
    Network::get_quic()
    {
        return (quic_manager) ? quic_manager.get() : nullptr;
    }


    void
    Network::shutdown_test()
    {
        quic_manager->close(true);
        quic_manager.reset();
        fprintf(stderr, "Test framework shut down, tunnel manager deleted\n");
    }


    void
    Network::listen(std::string host, uint16_t port)
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


    //  May be unneeded
    int 
    Network::configure_tunnel(Handler* handler) 
    {
        return 0;
    }


    /****** TEST FUNCTIONS ******/

    void
    Network::listen_test(Address& local)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try
        {
            ep->echo_server_test(local.ip, local.port);
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
    Network::send_oneshot_test(Address& local, Address& remote, std::string msg)
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
                local.ip, local.port, remote.ip, remote.port, msg);
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
    Network::listen_nullcert_test(Address& local, TLSCert cert)
    {
        auto ep = get_quic();
        if (ep == nullptr)
        {
            fprintf(stderr, "Error: Context was not initialized with tunnel manager object\n");
            return;
        }

        try
        {
            ep->echo_server_test(local.ip, local.port);
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
    Network::send_oneshot_nullcert_test(Address& local, Address& remote, TLSCert cert, std::string msg)
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
                local.ip, local.port, remote.ip, remote.port, msg);
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
