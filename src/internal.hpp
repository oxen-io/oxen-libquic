#pragma once

#include "format.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include <cstddef>

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    namespace log = oxen::log;

    using namespace log::literals;

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
            DATAGRAM_BATCH_SIZE;
#else
            1;
#endif

    namespace detail
    {
        // Wrapper around inet_pton that throws an exception on error
        inline void parse_addr(int af, void* dest, const std::string& from)
        {
            auto rv = inet_pton(af, from.c_str(), dest);

            if (rv == 0)  // inet_pton returns this on invalid input
                throw std::invalid_argument{"Unable to parse IP address!"};
            if (rv < 0)
                throw std::system_error{errno, std::system_category()};
        }

        // Parses an IPv4 address from string
        inline void parse_addr(in_addr& into, const std::string& from)
        {
            parse_addr(AF_INET, &into.s_addr, from);
        }

        // Parses an IPv6 address from string
        inline void parse_addr(in6_addr& into, const std::string& from)
        {
            parse_addr(AF_INET6, &into, from);
        }
    }  // namespace detail

}  // namespace oxen::quic
