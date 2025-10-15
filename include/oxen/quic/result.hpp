#pragma once

#include "utils.hpp"

#include <ngtcp2/ngtcp2.h>

#include <cstdint>
#include <exception>
#include <string>

#ifdef _WIN32
#include <array>
#endif

namespace oxen::quic
{
    // Maximum allowed application error code; this is defined by the QUIC protocol itself, that
    // uses 2 bits of an integer to indicate the integer length.
    inline constexpr uint64_t APP_ERRCODE_MAX = (1ULL << 62) - 1;

    // Stream/connection error codes.  We put our libquic-generated error codes as 777'000'000 + n
    // just because that makes it recognizable and is big enough to be unlikely to interfere with
    // application error codes, without going so big that we need 64-bit encoding.
    inline constexpr uint64_t ERROR_BASE = 777'000'000;

    // Error code we pass to a stream close callback if the stream is closed because the connection
    // is closing.
    inline constexpr uint64_t STREAM_ERROR_CONNECTION_CLOSED = ERROR_BASE + 1;

    // Application error code we close with if the stream data handle throws
    inline constexpr uint64_t STREAM_ERROR_EXCEPTION = ERROR_BASE + 100;

    // Application error if a bt request stream handle throws an exception
    inline constexpr uint64_t BTREQ_ERROR_EXCEPTION = ERROR_BASE + 105;

    // Application error code we close with if the datagram data handle throws
    inline constexpr uint64_t DATAGRAM_ERROR_EXCEPTION = ERROR_BASE + 200;

    /// Custom exception type that a stream handler can throw to send a custom stream error code to
    /// the other side.
    class application_stream_error : public std::exception
    {
      public:
        uint64_t code;

        explicit application_stream_error(uint64_t errcode) :
                code{errcode}, _what{"application error " + std::to_string(errcode)}
        {}
        const char* what() const noexcept override { return _what.c_str(); }

      private:
        std::string _what;
    };

    // Failed to write connection close:
    inline constexpr uint64_t CONN_WRITE_CLOSE_FAIL = ERROR_BASE + 1000;
    // Failed to send connection close:
    inline constexpr uint64_t CONN_SEND_CLOSE_FAIL = ERROR_BASE + 1001;
    // Failed to write packet
    inline constexpr uint64_t CONN_SEND_FAIL = ERROR_BASE + 1002;
    // Connection closing because it reached idle timeout
    inline constexpr uint64_t CONN_IDLE_CLOSED = ERROR_BASE + 1003;
    // Early data rejected:
    inline constexpr uint64_t CONN_EARLY_DATA_REJECTED = ERROR_BASE + 1004;
    // Stateless reset received
    inline constexpr uint64_t CONN_STATELESS_RESET = ERROR_BASE + 1005;

    std::string quic_strerror(uint64_t e);

    struct ngtcp2_error_code_t final
    {};

    // Tag value to pass into the io_result constructor to indicate an ngtcp2 error code.  (For
    // ngtcp2, error codes are arbitrary negative values without any connection to errno).
    inline constexpr ngtcp2_error_code_t ngtcp2_error_code{};

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
        std::conditional_t<IN_HELL, std::string, std::string_view> str_error() const;
    };

    struct io_error
    {
      private:
        uint64_t _code{0};

      public:
        bool is_ngtcp2 = false;

        io_error() = default;
        // explicit unsigned int constructor for NGTCP2 error macros
        // https://github.com/ngtcp2/ngtcp2/blob/ff7515bfbd9a503ac66f2b919acb92d2743c99e0/lib/includes/ngtcp2/ngtcp2.h#L952
        explicit io_error(unsigned int e) : _code{static_cast<uint64_t>(e)}, is_ngtcp2{true} {}
        explicit io_error(int e) : _code{static_cast<uint64_t>(e)}, is_ngtcp2{true} {}
        explicit io_error(uint64_t e) : _code{e} {}

        uint64_t code() const { return _code; }

        int ngtcp2_code() const { return static_cast<int>(_code); }

        uint64_t ngtcp2() const;

        std::string strerror() const;
    };

}  // namespace oxen::quic
