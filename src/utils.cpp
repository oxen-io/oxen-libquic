#include "utils.hpp"

#include <atomic>
#include <chrono>

extern "C"
{
#include <netinet/in.h>
#include <uv.h>
}

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
    uint64_t get_timestamp()
    {
        return std::chrono::nanoseconds{std::chrono::steady_clock::now().time_since_epoch()}.count();
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

    Address::Address(const std::string& addr, uint16_t port)
    {
        if (addr.empty())
        {
            // Default to all-0 IPv6 address, which is good (it's `::`, the IPv6 any addr)
            reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_port = port;
        }
        int rv;
        if (addr.find(':') != std::string_view::npos)
        {
            rv = uv_ip6_addr(addr.c_str(), port, reinterpret_cast<sockaddr_in6*>(&_sock_addr));
            _addr.addrlen = sizeof(sockaddr_in6);
        }
        else
        {
            rv = uv_ip4_addr(addr.c_str(), port, reinterpret_cast<sockaddr_in*>(&_sock_addr));
            _addr.addrlen = sizeof(sockaddr_in);
        }
        if (rv != 0)
            throw std::invalid_argument{"Cannot construct address: invalid IP"};
    }

    std::string Address::to_string() const
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (is_ipv6())
        {
            uv_ip6_name(*this, buf, sizeof(buf));
            return "[{}]:{}"_format(buf, port());
        }
        uv_ip4_name(*this, buf, sizeof(buf));
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

    std::string_view io_result::str() const
    {
        return is_libuv ? uv_strerror(error_code) : is_ngtcp2 ? ngtcp2_strerror(error_code) : strerror(error_code);
    }

}  // namespace oxen::quic
