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
            explicit max_streams(int s) : stream_count(s) {}
        };

    }  // namespace opt

}  // namespace oxen::quic
