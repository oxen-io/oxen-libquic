#include "opt.hpp"

namespace oxen::quic
{
    namespace opt
    {
        server_tls::server_tls(
                std::string server_key, std::string server_cert, std::string client_cert, std::string client_ca)
        {
            log::trace(log_cat, "server_tls constructor");
            private_key = datum{server_key};
            local_cert = datum{server_cert};
            if (!client_cert.empty())
                remote_cert = datum{client_cert};
            if (!client_ca.empty())
                remote_ca = datum{client_ca};
            scheme = context_init_scheme(0);
            _server_cred_init();
        }

        client_tls::client_tls(
                std::string client_key, std::string client_cert, std::string server_cert, std::string server_ca, client_tls_callback_t client_cb)
        {
            log::trace(log_cat, "client_tls constructor");
            private_key = datum{client_key};
            local_cert = datum{client_cert};
            if (!server_cert.empty())
                remote_cert = datum{server_cert};
            if (!server_ca.empty())
                remote_ca = datum{server_ca};
            if (client_cb)
                client_tls_cb = std::move(client_cb);
            scheme = context_init_scheme(1);
            _client_cred_init();
        }
    }  // namespace opt
}  // namespace oxen::quic
