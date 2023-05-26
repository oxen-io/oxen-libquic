#pragma once

#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    //

    namespace opt
    {
        struct local_addr : public Address
        {
            using Address::Address;
        };
        struct remote_addr : public Address
        {
            using Address::Address;
        };
        struct remote_tls : public GNUTLSCert
        {
            using GNUTLSCert::GNUTLSCert;
        };
        struct local_tls : public GNUTLSCert
        {
            using GNUTLSCert::GNUTLSCert;
        };
        struct server_tls : public GNUTLSCert
        {
            explicit server_tls(
                    std::string server_key,
                    std::string server_cert,
                    std::string client_cert = "",
                    std::string client_ca = "");
            std::shared_ptr<TLSContext> into_context() &&;
        };
        struct client_tls : public GNUTLSCert
        {
            explicit client_tls(
                    std::string client_key,
                    std::string client_cert,
                    std::string server_cert = "",
                    std::string server_ca = "",
                    client_tls_callback_t client_cb = nullptr);
            std::shared_ptr<TLSContext> into_context() &&;
        };

        inline std::shared_ptr<TLSContext> opt::server_tls::into_context() &&
        {
            return std::make_shared<GNUTLSContext>(*this);
        }

        inline std::shared_ptr<TLSContext> opt::client_tls::into_context() &&
        {
            return std::make_shared<GNUTLSContext>(*this);
        }

    }  // namespace opt

}  // namespace oxen::quic
