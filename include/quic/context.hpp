#pragma once

#include <memory>
#include <unordered_map>

#include "crypto.hpp"
#include "opt.hpp"
#include "stream.hpp"
#include "udp.hpp"
#include "utils.hpp"

namespace oxen::quic
{
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
        std::shared_ptr<TLSCreds> tls_creds;
        stream_data_callback_t stream_data_cb;
        stream_open_callback_t stream_open_cb;
        stream_close_callback_t stream_close_cb;
        config_t config{};

        // TODO: I think we can move the handle_opt calls here

        virtual ~ContextBase() = default;
    };

    struct OutboundContext : public ContextBase
    {
        template <typename... Opt>
        OutboundContext(Opt&&... opts)
        {
            log::trace(log_cat, "Making outbound session context...");
            // parse all options
            ((void)handle_outbound_opt(std::forward<Opt>(opts)), ...);

            log::debug(log_cat, "Outbound session context created successfully");
        }

      private:
        void handle_outbound_opt(std::shared_ptr<TLSCreds> tls);
        void handle_outbound_opt(opt::max_streams ms);
        void handle_outbound_opt(stream_data_callback_t func);
        void handle_outbound_opt(stream_open_callback_t func);
        void handle_outbound_opt(stream_close_callback_t func);
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
        void handle_inbound_opt(std::shared_ptr<TLSCreds> tls);
        void handle_inbound_opt(opt::max_streams ms);
        void handle_inbound_opt(stream_data_callback_t func);
        void handle_inbound_opt(stream_open_callback_t func);
        void handle_inbound_opt(stream_close_callback_t func);
    };

    /*
        1:1 with connection:
            stream data cb
            stream open cb
            max streams
    */

}  // namespace oxen::quic
