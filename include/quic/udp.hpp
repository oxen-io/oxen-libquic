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

#include "utils.hpp"

namespace oxen::quic
{
#ifdef _WIN32
    using msghdr = WSAMSG;
#else
    using msghdr = ::msghdr;
#endif

    // Simple struct wrapping a packet and its corresponding information
    struct Packet
    {
        Path path;
        bstring_view data;
        ngtcp2_pkt_info pkt_info{};

        /// Constructs a packet from a path and data:
        Packet(Path p, bstring_view d) : path{std::move(p)}, data{std::move(d)} {}

        /// Constructs a packet from a local address, data, and the IP header; remote addr and ECN
        /// data are extracted from the header.

        Packet(const Address& local, bstring_view data, msghdr& hdr);
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

        using receive_callback_t = std::function<void(const Packet& pkt)>;

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

        /// Returns the local address of this UDP socket
        const Address& address() const { return bound_; }

        /// Attempts to send one or more UDP payloads to a single destination.  Returns a pair: an
        /// io_result of either success (all packets were sent), `blocked()` if some or all of the
        /// packets could not be sent, or otherwise a `failure()` on more serious errors; and the
        /// number of packets that were actually sent (between 0 and n_pkts).
        ///
        /// Payloads should be packed sequentially starting at `bufs` with the length of each
        /// payload given by the `bufsize` array.  The ecn flag on the socket will be updated to the
        /// given ecn value (if not already set to it).
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
                const Address& dest, const std::byte* bufs, const size_t* bufsize, uint8_t ecn, size_t n_pkts);

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
        uint8_t ecn_{0};
        void set_ecn();

        event_base* ev_ = nullptr;

        event_ptr rev_ = nullptr;
        receive_callback_t receive_callback_;
        event_ptr wev_ = nullptr;
        std::vector<std::function<void()>> writeable_callbacks_;
    };

}  // namespace oxen::quic
