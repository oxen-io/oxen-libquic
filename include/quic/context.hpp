#pragma once

#include "tunnel.hpp"
#include "utils.hpp"

#include <uvw/loop.h>

#include <memory>

namespace oxen::quic
{
    /// Main library context 
    class Context
    {
        public:
            Context();
            ~Context();

            void
            init();

            std::shared_ptr<uvw::Loop>
    		loop();

            int
            socket();

            int
            next_socket_id();

            Tunnel*
            get_quic();

            void
            server_call(uint16_t port);

            void
            client_call(Address& local_addr, std::string remote_host, uint16_t remote_port, open_callback open_cb = NULL, close_callback close_cb = NULL);

            std::shared_ptr<uvw::Loop> ev_loop;
            
        protected:
            std::unique_ptr<oxen::quic::Tunnel> quic_manager;

            void
            on_open(Address& local_addr, std::string remote_host, int remote_port, void* user_data, bool success, open_callback open_cb = NULL);

            void
            on_close(Address& local_addr, std::string remote_host, int remote_port, void* user_data, int rv, close_callback close_cb = NULL);

            int 
            configure_tunnel(Tunnel* tunnel);

        private:
            // tracks the last used socket
            int _socket_id = 0;
            

    };

}   // namespace oxen::quic
