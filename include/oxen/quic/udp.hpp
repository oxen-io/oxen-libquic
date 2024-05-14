#pragma once

extern "C"
{
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <mswsock.h>
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
}

#include <event2/event.h>

#include <cstdint>
#include <variant>

#include "address.hpp"
#include "types.hpp"

namespace oxen::quic
{

#ifdef _WIN32
    using msghdr = WSAMSG;
    using cmsghdr = WSACMSGHDR;
#else
    using msghdr = ::msghdr;
#endif

    // Simple struct wrapping a raw packet and its corresponding information
    struct Packet
    {
      private:
        explicit Packet() = default;

      public:
        Path path;
        ngtcp2_pkt_info pkt_info{};
        std::variant<bstring_view, bstring> pkt_data;

        template <oxenc::basic_char Char = std::byte>
        std::basic_string_view<Char> data() const
        {
            return std::visit(
                    [](const auto& d) {
                        return std::basic_string_view<Char>{reinterpret_cast<const Char*>(d.data()), d.size()};
                    },
                    pkt_data);
        }

        bool operator==(const Packet& other) const { return (path == other.path) and (data() == other.data()); }

        bool operator!=(const Packet& other) const { return !(*this == other); }

        /// Constructs a packet from a path and data view:
        Packet(Path p, bstring_view d) : path{std::move(p)}, pkt_data{std::move(d)} {}

        /// Constructs a packet from a path and transferred data:
        Packet(Path p, bstring&& d) : path{std::move(p)}, pkt_data{std::move(d)} {}

        /// Constructs a packet from a local address, data, and the IP header; remote addr and ECN
        /// data are extracted from the header.
        Packet(const Address& local, bstring_view data, msghdr& hdr);

        std::string bt_encode() const;

        static std::optional<Packet> bt_decode(bstring buf);
    };

    /// RAII class wrapping a UDP socket; the socket is bound at construction and closed during
    /// destruction.
    class UDPSocket
    {
      public:
        using socket_t =
#ifndef _WIN32
                int
#else
                SOCKET
#endif
                ;

        using receive_callback_t = std::function<void(Packet&& pkt)>;

        UDPSocket() = delete;

        /// Constructs a UDP socket bound to the given address.  Throws if binding fails.  If
        /// binding to an any address (or any port) you can retrieve the realized address via
        /// address() after construction.
        ///
        /// When packets are received they will be fed into the given callback.
        ///
        /// ev_loop must outlive this object.
        UDPSocket(event_base* ev_loop, const Address& addr, receive_callback_t cb);

        /// Non-copyable and non-moveable
        UDPSocket(const UDPSocket& s) = delete;
        UDPSocket& operator=(const UDPSocket& s) = delete;
        UDPSocket(UDPSocket&& s) = delete;
        UDPSocket& operator=(UDPSocket&& s) = delete;

        /// Returns the bound local address of this UDP socket.  Note that this is not necessarily
        /// the same as the Path's local address for incoming packets (this could be, for instance,
        /// bound to an "any" address, while incoming packets will have the actual IP address the
        /// packet arrived on).
        const Address& address() const { return bound_; }

        /// Attempts to send one or more UDP payloads on a single path.  Returns a pair: an
        /// io_result of either success (all packets were sent), `blocked()` if some or all of the
        /// packets could not be sent, or otherwise a `failure()` on more serious errors; and the
        /// number of packets that were actually sent (between 0 and n_pkts).
        ///
        /// Payloads should be packed sequentially starting at `bufs` with the length of each
        /// payload given by the `bufsize` array.  The given ecn value will be used for the packets.
        ///
        /// If not all packets could be sent because the socket would block it is up to the caller
        /// to deal with it: if such a block occurs it is always the first `n` packets that will
        /// have been sent; the caller then has to decide whether to drop the rest, or hold onto
        /// them to queue later, etc. (that is: this class does not take care of that).
        ///
        /// Typically this is done by blocking creation of new packets and using `when_writeable` to
        /// retry however much of the send is remaining (via resend()) and, once the send is fully
        /// completed, resuming creation of new packets.
        std::pair<io_result, size_t> send(
                const Path& path, const std::byte* bufs, const size_t* bufsize, uint8_t ecn, size_t n_pkts);

        /// Queues a callback to invoke when the UDP socket becomes writeable again.
        ///
        /// This should be called immediately after `send()` returns a `.blocked()` status to
        /// trigger a resend as soon as the socket blockage clears, and secondly to stop producing
        /// new packets until the blockage clears.  (Note that it is possible for this subsequent
        /// send to block again, in which case the caller should rinse and repeat).
        void when_writeable(std::function<void()> cb);

        /// Closed on destruction
        ~UDPSocket();

      private:
        void process_packet(bstring_view payload, msghdr& hdr);
        io_result receive();

        socket_t sock_;
        Address bound_;

        event_base* ev_ = nullptr;

        event_ptr rev_ = nullptr;
        receive_callback_t receive_callback_;
        event_ptr wev_ = nullptr;
        std::vector<std::function<void()>> writeable_callbacks_;
    };

}  // namespace oxen::quic
