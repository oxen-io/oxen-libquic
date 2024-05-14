#pragma once

#include "utils.hpp"

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

    // Application error code for signalling a remote shut down stream reading
    inline constexpr uint64_t STREAM_REMOTE_READ_SHUTDOWN = ERROR_BASE + 101;

    // Application error code for signalling a remote shut down stream writing
    inline constexpr uint64_t STREAM_REMOTE_WRITE_SHUTDOWN = ERROR_BASE + 102;

    // Application error if a bt request stream handle throws an exception
    inline constexpr uint64_t BPARSER_ERROR_EXCEPTION = ERROR_BASE + 105;

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

    inline std::string quic_strerror(uint64_t e)
    {
        switch (e)
        {
            case 0:
                return "No error"s;
            case DATAGRAM_ERROR_EXCEPTION:
                return "Error - datagram exception"s;
            case STREAM_ERROR_EXCEPTION:
                return "Error - stream exception"s;
            case BPARSER_ERROR_EXCEPTION:
                return "Error - bt request stream exception"s;
            case STREAM_ERROR_CONNECTION_CLOSED:
                return "Error - stream connection closed"s;
            case CONN_WRITE_CLOSE_FAIL:
                return "Error - Failed to write connection close"s;
            case CONN_SEND_CLOSE_FAIL:
                return "Error - Failed to send connection close"s;
            case CONN_SEND_FAIL:
                return "Error - Failed to send packet"s;
            case CONN_IDLE_CLOSED:
                return "Connection closed by idle timeout"s;
            default:
                return "Application error code " + std::to_string(e);
        }
    }

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

        std::string strerror() const { return is_ngtcp2 ? ngtcp2_strerror(static_cast<int>(_code)) : quic_strerror(_code); }
    };

}  // namespace oxen::quic
