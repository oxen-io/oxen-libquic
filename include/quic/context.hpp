#pragma once

#include <memory>
#include <unordered_map>

#include "crypto.hpp"
#include "datagram.hpp"
#include "opt.hpp"
#include "stream.hpp"
#include "udp.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    // created to store user configuration values; more values to be added later
    struct user_config
    {
        // max streams
        uint64_t max_streams = 0;
        // datagram support
        bool datagram_support = false;
        // datagram splitting support
        bool split_packet = false;
        // splitting policy
        Splitting policy = Splitting::NONE;

        user_config() = default;
    };

    struct IOContext
    {
      public:
        Direction dir;
        std::shared_ptr<TLSCreds> tls_creds;
        stream_data_callback stream_data_cb;
        stream_open_callback stream_open_cb;
        stream_close_callback stream_close_cb;
        stream_constructor_callback stream_construct_cb;
        connection_established_callback conn_established_cb;
        connection_closed_callback conn_closed_cb;
        user_config config{};

        template <typename... Opt>
        IOContext(Direction d, Opt&&... opts) : dir{d}
        {
            log::trace(log_cat, "Making IO session context");
            // parse all options
            ((void)handle_ioctx_opt(std::forward<Opt>(opts)), ...);

            if (tls_creds == nullptr)
                throw std::runtime_error{"Session IOContext requires some form of TLS credentials to operate"};

            log::debug(
                    log_cat, "{} IO context created successfully", (dir == Direction::OUTBOUND) ? "Outbound"s : "Inbound"s);
        }

        ~IOContext() = default;

      private:
        void handle_ioctx_opt(std::shared_ptr<TLSCreds> tls);
        void handle_ioctx_opt(opt::max_streams ms);
        void handle_ioctx_opt(stream_data_callback func);
        void handle_ioctx_opt(stream_open_callback func);
        void handle_ioctx_opt(stream_close_callback func);
        void handle_ioctx_opt(stream_constructor_callback func);
        void handle_ioctx_opt(connection_established_callback func);
        void handle_ioctx_opt(connection_closed_callback func);

        /// Unwraps an optional option: does nothing if nullopt, otherwise applies the option.  This
        /// is here to make runtime-dependent options (i.e. options whose presence depends on a
        /// condition not knowable at compile time) easier to manage.
        template <typename Opt>
        void handle_ioctx_opt(std::optional<Opt> option)
        {
            if (option)
                handle_ioctx_opt(std::move(*option));
        }
    };

}  // namespace oxen::quic
