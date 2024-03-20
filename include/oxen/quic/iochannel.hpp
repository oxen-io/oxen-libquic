#pragma once
#include "connection_ids.hpp"
#include "messages.hpp"
#include "utils.hpp"

namespace oxen::quic
{

    class Connection;
    class Endpoint;
    class Stream;

    class IOChannel
    {
      protected:
        IOChannel(Connection& c, Endpoint& e);

      public:
        virtual ~IOChannel() = default;

        Endpoint& endpoint;
        const ConnectionID reference_id;

        // no copy, no move. always hold in a shared pointer
        IOChannel(const IOChannel&) = delete;
        IOChannel& operator=(const IOChannel&) = delete;
        IOChannel(IOChannel&&) = delete;
        IOChannel& operator=(IOChannel&&) = delete;

        virtual bool is_stream() const = 0;
        virtual std::shared_ptr<Stream> get_stream() = 0;
        virtual int64_t stream_id() const = 0;

        // These public methods are intended for access from anywhere and invoke a call_get to
        // synchronously get their value.  (Subclasses provide implementations by overriding the
        // protected _impl versions of these methods).
        bool is_empty() const;
        size_t unsent() const;
        bool has_unsent() const;
        bool is_closing() const;

        // These are call_get-proxied to return the value from the Connection object.  They throw if
        // the Connection object no longer exists.
        Path path() const;
        Address local() const;
        Address remote() const;

        // Sends a string_view of character/byte data.  The keep_alive argument is used to manage
        // ownership: it will be held until the data is completely sent and acked by the remote
        // side.  It can be nullptr to disable, but only if the caller is certain that the provided
        // data will stay alive for the duration of the Stream's lifetime.
        template <typename CharType, std::enable_if_t<sizeof(CharType) == 1, int> = 0>
        void send(std::basic_string_view<CharType> data, std::shared_ptr<void> keep_alive)
        {
            send_impl(convert_sv<std::byte>(data), std::move(keep_alive));
        }

        // Takes over ownership of a string of character/byte data and sends it into the stream.
        template <typename CharType>
        void send(std::basic_string<CharType>&& data)
        {
            auto keep_alive = std::make_shared<std::basic_string<CharType>>(std::move(data));
            std::basic_string_view<CharType> view{*keep_alive};
            send(view, std::move(keep_alive));
        }

        // Takes over ownership of a vector of character/byte data and sends it into the stream.
        template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
        void send(std::vector<Char>&& buf)
        {
            send(std::basic_string_view<Char>{buf.data(), buf.size()}, std::make_shared<std::vector<Char>>(std::move(buf)));
        }

      protected:
        friend class Connection;
        friend struct rotating_buffer;

        Connection* _conn;

        // This is the (single) send implementation that implementing classes must provide; other
        // calls to send are converted into calls to this.
        virtual void send_impl(bstring_view, std::shared_ptr<void> keep_alive) = 0;

        virtual std::vector<ngtcp2_vec> pending() = 0;
        virtual prepared_datagram pending_datagram(bool) = 0;
        virtual bool sent_fin() const = 0;
        virtual void set_fin(bool) = 0;
        virtual void wrote(size_t) = 0;

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
                typename Class,
                typename T,
                typename Ret = remove_cvref_t<T>,
                typename EP = std::enable_if_t<std::is_base_of_v<IOChannel, Class>, Endpoint>>
        Ret call_get_accessor(T (Class::*getter)() const) const
        {
            return static_cast<EP&>(endpoint).call_get(
                    [this, &getter]() -> Ret { return (static_cast<const Class*>(this)->*getter)(); });
        }

        // Wraps a Connection accessor member function pointer in a call_get for synchronous access
        // that always returns by value (even if the member function returns by reference) through
        // the IOChannel's connection pointer.  Throws if the Connection doesn't exist anymore.
        template <typename T, typename Ret = remove_cvref_t<T>, typename EP = Endpoint>
        Ret call_get_accessor(T (Connection::*getter)() const) const
        {
            // This do-nothing static cast to force deferred instantiation until later on (when the
            // Endpoint class will be available).  Otherwise this won't compile because Endpoint
            // is only forward declared here.
            return static_cast<EP&>(endpoint).call_get([this, &getter]() -> Ret {
                if (!_conn)
                    throw std::runtime_error{"Connection has gone away"};
                return (_conn->*getter)();
            });
        }
    };

}  // namespace oxen::quic
