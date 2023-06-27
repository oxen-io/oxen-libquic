#pragma once

#include <memory>
#include <unordered_map>
#include <uvw.hpp>

#include "crypto.hpp"
#include "opt.hpp"
#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint;

    // created to store user configuration values; more values to be added later
    struct config_t
    {
        // max streams
        int max_streams = 0;

        config_t() = default;
    };

    struct ContextBase
    {
      public:
        Address local, remote;
        std::shared_ptr<TLSCreds> tls_creds;
        stream_data_callback_t stream_data_cb;
        stream_open_callback_t stream_open_cb;
        config_t config{};

        virtual ~ContextBase() = default;
    };

    struct OutboundContext : public ContextBase
    {
        // Cert information for each connection is stored in a map indexed by ConnectionID.
        // As a result, each connection (also mapped in client->conns) can have its own
        // TLS cert info. Each connection also stores within it the gnutls_session_t and
        // gnutls_certificate_credentials_t objects used to initialize its ngtcp2 things

        template <typename... Opt>
        OutboundContext(Opt&&... opts)
        {
            log::trace(log_cat, "Making outbound session context...");
            // parse all options
            ((void)handle_outbound_opt(std::forward<Opt>(opts)), ...);

            log::debug(log_cat, "Outbound session context created successfully");
        }

      private:
        void handle_outbound_opt(opt::local_addr addr);
        void handle_outbound_opt(opt::remote_addr addr);
        void handle_outbound_opt(std::shared_ptr<TLSCreds> tls);
        void handle_outbound_opt(opt::max_streams ms);
        void handle_outbound_opt(stream_data_callback_t func);
        void handle_outbound_opt(stream_open_callback_t func);

        inline void set_local(Address& addr) { local = Address{addr}; }
        inline void set_remote(Address& addr) { remote = Address{addr}; }
    };

    struct InboundContext : public ContextBase
    {
        template <typename... Opt>
        InboundContext(Opt&&... opts)
        {
            log::trace(log_cat, "Making inbound session context...");
            // parse all options
            ((void)handle_inbound_opt(std::forward<Opt>(opts)), ...);

            log::debug(log_cat, "Inbound session context successfully created");
        }

      private:
        void handle_inbound_opt(opt::local_addr addr);
        void handle_inbound_opt(Address addr);
        void handle_inbound_opt(std::shared_ptr<TLSCreds> tls);
        void handle_inbound_opt(stream_data_callback_t func);
        void handle_inbound_opt(stream_open_callback_t func);
        void handle_inbound_opt(opt::max_streams ms);
    };

}  // namespace oxen::quic
