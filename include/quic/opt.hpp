#pragma once

#include <stdexcept>

#include "address.hpp"
#include "crypto.hpp"
#include "types.hpp"

namespace oxen::quic::opt
{
    using namespace std::chrono_literals;

    struct max_streams
    {
        uint64_t stream_count{DEFAULT_MAX_BIDI_STREAMS};
        max_streams() = default;
        explicit max_streams(uint64_t s) : stream_count{s} {}
    };

    struct keep_alive
    {
        std::chrono::milliseconds time{0ms};
        keep_alive() = default;
        explicit keep_alive(std::chrono::milliseconds val) : time{val} {}
    };

    /// This can be initialized a few different ways. Simply passing a default constructed struct
    /// to Network::Endpoint(...) will enable datagrams without packet-splitting. From there, pass
    /// `Splitting::ACTIVE` to the constructor to enable packet-splitting.
    ///
    /// The size of the rotating datagram buffer can also be specified as a second parameter to the
    /// constructor. Buffer size is subdivided amongst 4 equally sized buffer rows, so the bufsize
    /// must be perfectly divisible by 4
    ///
    /// In some use cases, the user may want the receive data as a string view or a string literal.
    /// The default is string literal; setting
    ///
    /// The max size of a transmittable datagram can be queried directly from connection_interface::
    /// get_max_datagram_size(). At connection initialization, ngtcp2 will default this value to 1200.
    /// The actual value is negotiated upwards via path discovery, reaching a theoretical maximum of
    /// NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE (1452), or near it, per datagram. Please note that enabling
    /// datagram splitting will double whatever value is returned.
    ///
    /// Note: this setting CANNOT be changed for an endpoint after creation, it must be
    /// destroyed and re-initialized with the desired settings.
    struct enable_datagrams
    {
        bool split_packets{false};
        Splitting mode{Splitting::NONE};
        // Note: this is the size of the entire buffer, divided amongst 4 rows
        int bufsize{4096};

        enable_datagrams() = default;
        explicit enable_datagrams(bool e) = delete;
        explicit enable_datagrams(Splitting m) : split_packets{true}, mode{m} {}
        explicit enable_datagrams(Splitting m, int b) : split_packets{true}, mode{m}, bufsize{b}
        {
            if (b <= 0)
                throw std::out_of_range{"Bufsize must be positive"};
            if (b > 1 << 14)
                throw std::out_of_range{"Bufsize too large"};
            if (b % 4 != 0)
                throw std::invalid_argument{"Bufsize must be evenly divisible between 4 rows"};
        }
    };

    // supported ALPNs for outbound connections
    struct outbound_alpns
    {
        std::vector<ustring> alpns;
        explicit outbound_alpns(std::vector<ustring> alpns = {}) : alpns{std::move(alpns)} {}
    };

    // supported ALPNs for inbound connections
    struct inbound_alpns
    {
        std::vector<ustring> alpns;
        explicit inbound_alpns(std::vector<ustring> alpns = {}) : alpns{std::move(alpns)} {}
    };

    struct handshake_timeout
    {
        std::chrono::nanoseconds timeout;
        explicit handshake_timeout(std::chrono::nanoseconds ns = 0ns) : timeout{ns} {}
    };

}  // namespace oxen::quic::opt
