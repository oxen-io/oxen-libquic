#pragma once

#include "utils.hpp"

namespace oxen::quic
{
    struct ngtcp2_error_code_t final
    {};

    // Tag value to pass into the constructor to indicate an ngtcp2 error code.
    //
    // (For ngtcp2, error codes are arbitrary negative values without any connection to errno).
    static inline constexpr ngtcp2_error_code_t ngtcp2_error_code{};

    enum class Direction { OUTBOUND = 0, INBOUND = 1 };

    enum class Splitting { NONE = 0, LAZY = 1, GREEDY = 2 };

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

        // Same as the ngtcp2 error code constructor
        static io_result ngtcp2(int err) { return io_result{err, ngtcp2_error_code}; }

        // The numeric error code
        int error_code{0};
        // If true then `error_code` is an ngtcp2 error code, rather than an errno value.
        bool is_ngtcp2 = false;
        // Returns true if this indicates success, i.e. error code of 0
        bool success() const { return error_code == 0; }
        // Returns true if this indicates failure, i.e. error code not 0
        bool failure() const { return !success(); }
        // returns true if error value indicates a failure to write without blocking
        bool blocked() const
        {
            return is_ngtcp2 ? error_code == NGTCP2_ERR_STREAM_DATA_BLOCKED
                             : (error_code == EAGAIN || error_code == EWOULDBLOCK);
        }

        // returns the error message string describing error_code
        std::string_view str_error() const { return is_ngtcp2 ? ngtcp2_strerror(error_code) : strerror(error_code); };
    };
}  // namespace oxen::quic
