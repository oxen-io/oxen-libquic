#pragma once

#ifdef _WIN32
#include <array>
#endif

#include "utils.hpp"

namespace oxen::quic
{
    enum class Direction { OUTBOUND = 0, INBOUND = 1 };

    enum class Splitting { NONE = 0, ACTIVE = 1 };

    // Struct returned as a result of send_packet that either is implicitly
    // convertible to bool, but also is able to carry an error code
    struct io_result
    {
        // Default construction makes a "good" io_result, i.e. with error code 0
        io_result() : io_result{0} {}

        // Constructs an io_result with an `errno` value.
        explicit io_result(int errno_val) : error_code{errno_val} {}

        // Constructs an io_result with an ngtcp2 error value.
        io_result(int err, ngtcp2_error_code_t) : error_code{err}, is_ngtcp2{true} {}

#ifdef _WIN32
        static io_result wsa(int err)
        {
            io_result e{err};
            e.is_wsa = true;
            return e;
        }
#endif

        // Same as the ngtcp2 error code constructor
        static io_result ngtcp2(int err) { return io_result{err, ngtcp2_error_code}; }

        // The numeric error code
        int error_code{0};
        // If true then `error_code` is an ngtcp2 error code, rather than an errno value.
        bool is_ngtcp2 = false;
#ifdef _WIN32
        // If true then this is a WSALastErrorCode error code value.
        bool is_wsa = false;
#endif
        // Returns true if this indicates success, i.e. error code of 0
        bool success() const { return error_code == 0; }
        // Returns true if this indicates failure, i.e. error code not 0
        bool failure() const { return !success(); }
        // returns true if error value indicates a failure to write without blocking
        bool blocked() const
        {
            return is_ngtcp2 ? error_code == NGTCP2_ERR_STREAM_DATA_BLOCKED
#ifdef _WIN32
                 : is_wsa ? error_code == WSAEWOULDBLOCK
#endif
                          : (error_code == EAGAIN || error_code == EWOULDBLOCK);
        }

        // returns the error message string describing error_code
        // std::string_view str_error() const { return is_ngtcp2 ? ngtcp2_strerror(error_code) : strerror(error_code); };

        std::conditional_t<IN_HELL, std::string, std::string_view> str_error() const
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
                return "Unknown error "s.append(std::to_string(error_code));
            }
#endif
            if (is_ngtcp2)
                return ngtcp2_strerror(error_code);

            return strerror(error_code);
        }
    };
}  // namespace oxen::quic
