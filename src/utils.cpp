#include "utils.hpp"

#include <oxenc/endian.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>

#include "connection.hpp"

namespace oxen::quic
{
    void logger_config(std::string out, log::Type type, log::Level reset)
    {
        static std::atomic<bool> run_once{false};

        if (not run_once.exchange(true))
        {
            oxen::log::add_sink(type, out);
            oxen::log::reset_level(reset);
        }
    }

    std::chrono::steady_clock::time_point get_time()
    {
        return std::chrono::steady_clock::now();
    }
    std::chrono::nanoseconds get_timestamp()
    {
        return std::chrono::steady_clock::now().time_since_epoch();
    }

    std::string str_tolower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    std::mt19937 make_mt19937()
    {
        std::random_device rd;
        return std::mt19937(rd());
    }

    ConnectionID::ConnectionID(const uint8_t* cid, size_t length)
    {
        assert(length <= NGTCP2_MAX_CIDLEN);
        datalen = length;
        std::memmove(data, cid, datalen);
    }

    ConnectionID ConnectionID::random()
    {
        ConnectionID cid;
        cid.datalen = static_cast<size_t>(NGTCP2_MAX_CIDLEN);
        gnutls_rnd(GNUTLS_RND_RANDOM, cid.data, cid.datalen);
        return cid;
    }

    std::string ConnectionID::to_string() const
    {
        return "{:02x}"_format(fmt::join(std::begin(data), std::begin(data) + datalen, ""));
    }

    Address::Address(const std::string& addr, uint16_t port)
    {
        if (addr.empty())
        {
            // Default to all-0 IPv6 address, which is good (it's `::`, the IPv6 any addr)
            reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_port = oxenc::host_to_big(port);
        }
        int rv;
        if (addr.find(':') != std::string_view::npos)
        {
            _sock_addr.ss_family = AF_INET6;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            sin6.sin6_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in6);
            rv = inet_pton(AF_INET6, addr.c_str(), &sin6.sin6_addr);
        }
        else
        {
            _sock_addr.ss_family = AF_INET;
            auto& sin4 = reinterpret_cast<sockaddr_in&>(_sock_addr);
            sin4.sin_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in);
            rv = inet_pton(AF_INET, addr.c_str(), &sin4.sin_addr);
        }
        if (rv == 0)  // inet_pton returns this on invalid input
            throw std::invalid_argument{"Cannot construct address: invalid IP"};
        if (rv < 0)
            std::system_error{errno, std::system_category()};
    }

    std::string Address::to_string() const
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (is_ipv6())
        {
            inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_addr, buf, sizeof(buf));
            return "[{}]:{}"_format(buf, port());
        }
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_addr, buf, sizeof(buf));
        return "{}:{}"_format(buf, port());
    }

    std::string Path::to_string() const
    {
        return "{{{} ➙ {}}}"_format(local, remote);
    }

    std::string buffer_printer::to_string() const
    {
        auto& b = buf;
        std::string out;
        auto ins = std::back_inserter(out);
        fmt::format_to(ins, "Buffer[{}/{:#x} bytes]:", b.size(), b.size());

        for (size_t i = 0; i < b.size(); i += 32)
        {
            fmt::format_to(ins, "\n{:04x} ", i);

            size_t stop = std::min(b.size(), i + 32);
            for (size_t j = 0; j < 32; j++)
            {
                auto k = i + j;
                if (j % 4 == 0)
                    out.push_back(' ');
                if (k >= stop)
                    out.append("  ");
                else
                    fmt::format_to(ins, "{:02x}", std::to_integer<uint_fast16_t>(b[k]));
            }
            out.append(u8"  ┃");
            for (size_t j = i; j < stop; j++)
            {
                auto c = std::to_integer<char>(b[j]);
                if (c == 0x00)
                    out.append(u8"∅");
                else if (c < 0x20 || c > 0x7e)
                    out.append(u8"·");
                else
                    out.push_back(c);
            }
            out.append(u8"┃");
        }
        return out;
    }

    std::conditional_t<IN_HELL, std::string, std::string_view> io_result::str() const
    {
#ifdef _WIN32
        if (is_wsa)
        {
            std::array<char, 256> buf;
            buf[0] = 0;

            FormatMessage(
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr,
                    error_code,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    buf.data(),
                    buf.size(),
                    nullptr);
            if (buf[0])
                return buf.data();
            return "Unknown error {}"_format(error_code);
        }
#endif
        if (is_ngtcp2)
            return ngtcp2_strerror(error_code);

        return strerror(error_code);
    }

}  // namespace oxen::quic
