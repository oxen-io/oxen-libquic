#pragma once

#include "address.hpp"
#include "crypto.hpp"
#include "types.hpp"

namespace oxen::quic::opt
{
    struct local_addr : public Address
    {
        using Address::Address;

        // Constructing from just a port to bind to that port, any address
        explicit local_addr(uint16_t port) : Address{"", port} {}
    };

    struct remote_addr : public Address
    {
        using Address::Address;
    };

    struct max_streams
    {
        int stream_count = DEFAULT_MAX_BIDI_STREAMS;
        max_streams() = default;
        explicit max_streams(int s) : stream_count{s} {}
    };

    /// This can be initialized a few different ways. Simply passing a default constructed struct
    /// to Network::Endpoint(...) will enable datagrams without packet-splitting. From there, a
    /// 'true' boolean can be passed to the constructor to enable packet-splitting. The default
    /// mode is 'lazy', where the already split packets are handed to libQUIC to be sent out in
    /// pairs. 'Greedy' mode takes in a double-sized packet, splits it, and sends it out.
    ///
    /// In either mode, the max size of a transmittable datagram can be queried directly from
    /// connection_interface::get_max_datagram_size(). At connection initialization, ngtcp2 will
    /// default this value to 1200. The actual value is negotiated upwards via path discovery,
    /// reaching a theoretical maximum of NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE (1452), or near it.
    ///
    /// Note: this setting CANNOT be changed for an endpoint after creation, it must be
    /// destroyed and re-initialized with the desired settings.
    struct enable_datagrams
    {
        bool split_packets = false;
        Splitting mode = Splitting::NONE;

        enable_datagrams() = default;
        explicit enable_datagrams(bool e) = delete;
        explicit enable_datagrams(Splitting m) : split_packets{true}, mode{m} {}
    };

}  // namespace oxen::quic::opt
