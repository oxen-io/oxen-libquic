#pragma once

#include "address.hpp"
#include "connection_ids.hpp"
#include "utils.hpp"

#include <oxenc/common.h>

#include <ngtcp2/ngtcp2.h>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace oxen::quic
{

    class Connection;
    class Endpoint;
    class Loop;
    class Stream;
    namespace dgram
    {
        struct prepared;
    }

    /// Base class shared by streams and datagrams.
    class IOChannel
    {
      protected:
        IOChannel(Connection& c, Endpoint& e);

      public:
        virtual ~IOChannel() = default;

        Endpoint& endpoint;
        Loop& loop;

        // The fixed Connection reference_id.  This will be the same as `get_conn()->reference_id`
        // while the connection exists, but persists even if the connection object gets destroyed.
        const ConnectionID reference_id;

        // no copy, no move. always hold in a shared pointer
        IOChannel(const IOChannel&) = delete;
        IOChannel& operator=(const IOChannel&) = delete;
        IOChannel(IOChannel&&) = delete;
        IOChannel& operator=(IOChannel&&) = delete;

        virtual bool is_stream() const = 0;

        // Returns this channel's connection object.  Will return a nullptr if the Connection no
        // longer exists.
        std::shared_ptr<Connection> get_conn();

        // These public methods are intended for access from anywhere and invoke a call_get to
        // synchronously get their value.  (Subclasses provide implementations by overriding the
        // protected _impl versions of these methods).
        bool is_empty() const;
        size_t unsent() const;
        bool has_unsent() const;
        bool is_closing() const;

        void send(std::span<const std::byte> data, std::shared_ptr<void> keep_alive)
        {
            send_impl(data, std::move(keep_alive));
        }

        void send(std::span<const unsigned char> data, std::shared_ptr<void> keep_alive)
        {
            send_impl(reinterpret_span<const std::byte>(data), std::move(keep_alive));
        }

        void send(std::string_view data, std::shared_ptr<void> keep_alive)
        {
            send_impl(reinterpret_span<const std::byte>(data), std::move(keep_alive));
        }

        void send(std::string&& data);

        template <oxenc::basic_char Char>
        void send(std::vector<Char>&& buf)
        {
            auto keep_alive = std::make_shared<std::vector<Char>>(std::move(buf));
            auto bsp = reinterpret_span<const std::byte>(std::span{*keep_alive});
            send_impl(bsp, std::move(keep_alive));
        }

      protected:
        friend class Connection;
        friend struct rotating_buffer;

        Connection* _conn;

        // This is the (single) send implementation that implementing classes must provide; other
        // calls to send are converted into calls to this.
        virtual void send_impl(std::span<const std::byte>, std::shared_ptr<void> keep_alive) = 0;

        // Does the actual implementation: these methods may only be called internally, from code
        // already inside the event loop thread.  (The public non-_impl versions of these methods
        // are simply wrappers that use call_get to invoke these _impl versions).
        virtual bool is_empty_impl() const = 0;
        virtual size_t unsent_impl() const = 0;
        virtual bool has_unsent_impl() const = 0;
        virtual bool is_closing_impl() const = 0;

        // Wraps an IOChannel (or derived type) accessor member function pointer in a call_get for
        // synchronous access that always returns by value (even if the member function returns by
        // reference).
        template <
                std::derived_from<IOChannel> Class,
                typename T,
                typename Ret = std::remove_cvref_t<T>,
                typename EP = Endpoint>
        Ret call_get_accessor(T (Class::*getter)() const) const
        {
            return static_cast<EP&>(endpoint).loop.call_get(
                    [this, &getter]() -> Ret { return (static_cast<const Class*>(this)->*getter)(); });
        }
    };

}  // namespace oxen::quic
