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

        protected:
            std::unique_ptr<oxen::quic::Tunnel> quic_manager;

            int 
            configure_tunnel(Tunnel* tunnel);

        private:
            // tracks the last used socket
            int _socket_id = 0;
            

    };

}   // namespace oxen::quic
