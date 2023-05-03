#pragma once

#include "endpoint.hpp"
#include "handler.hpp"
#include "utils.hpp"

#include <cstddef>
#include <memory>
#include <stdlib.h>
#include <string_view>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <uvw.hpp>


namespace oxen::quic
{
    class ClientContext;
    
    class Client : public Endpoint
    {
        public:
            std::shared_ptr<ClientContext> context;

            Client(std::shared_ptr<Handler> quic_manager, std::shared_ptr<ClientContext> ctx, ConnectionID& id);
            ~Client();

            std::pair<ConnectionID&, std::shared_ptr<Connection>>
            make_conn(Address& remote, Address& local);

            // Writes 'data' to the connection specified by 'conn_id' or 'destination', depending on which overload
            // is being used. Returns the number of bytes successfully written.
            //
            size_t
            write(const char* data, ConnectionID conn_id);
            size_t
            write(const char* data, Address& destination);

            // Main client method for creating a new outbound connection. A dedicated UDPHandle will be bound to the
            // local address passed to this function; if not, UVW will pick a random local port to bind to. The creation
            // of a new outbound connection necessitates the creation of a new TLS context as well. The following 
            // three parameter structs can be passed to use this:
            // 
            //      local_addr
            // 
            // 
            // 
            template <typename ... Opt>
            void
            connect(Opt&&... opts)
            {
                //
            };

        private:

    };

}   // namespace oxen::quic
