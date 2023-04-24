#pragma once

#include "handler.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <uvw.hpp>

#include <cstdint>

#include <memory>

namespace oxen::quic
{
    /// Main library context 
    class Context
    {
        public:
            Context(std::shared_ptr<uvw::Loop> loop_ptr = nullptr);
            ~Context();

            void
            init();

            int
            socket();

            int
            next_socket_id();

            Handler*
            get_quic();

            void
            shutdown_test();

            void
            listen_to(std::string host, uint16_t port);

            template <typename T, std::enable_if_t<std::is_base_of_v<TLSCert, T>, bool> = true>
            void
            udp_connect(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
                T cert, open_callback open_cb = NULL, close_callback close_cb = NULL);

            void
            udp_connect(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
                open_callback open_cb = NULL, close_callback close_cb = NULL);

            /****** TEST FUNCTIONS ******/
            void
            listen_test(std::string host, uint16_t port);
            void
            send_oneshot_test(
                std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, std::string msg="");
            // TOFIX: add cert verification to nullcert tests
            void
            listen_nullcert_test(std::string host, uint16_t port, TLSCert cert);
            void
            send_oneshot_nullcert_test(std::string local_host, uint16_t local_port, std::string remote_host, uint16_t remote_port, 
                TLSCert cert, std::string msg="");
            /****************************/
        protected:
            std::unique_ptr<Handler> quic_manager;

            int 
            configure_tunnel(Handler* handler);

        private:            

    };

}   // namespace oxen::quic
