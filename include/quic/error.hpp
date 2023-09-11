#pragma once

#include "utils.hpp"

namespace oxen::quic
{

    enum class error : uint64_t {
        NO_ERR = 0,
        STREAM_CLOSE_NO_ERR = (1ULL << 62) - 96,
        CONN_CLOSE_NO_ERR = (1ULL << 62) - 95,
        CONN_DRAIN_NO_ERR = (1ULL << 62) - 94,

        DATAGRAM_EXCEPTION = (1ULL << 62) - 64,

        STREAM_EXCEPTION = (1ULL << 62) - 32,
        STREAM_CONNECTION_EXPIRED = (1ULL << 62) - 31,

        CONN_WRITE_CLOSE_FAIL = (1ULL << 62)
    };

    inline const char* quic_strerror(uint64_t e)
    {
        switch (static_cast<error>(e))
        {
            case error::NO_ERR:
                return "No error";
            case error::DATAGRAM_EXCEPTION:
                return "Error - datagram exception";
            case error::STREAM_CLOSE_NO_ERR:
                return "No error - closing stream";
            case error::STREAM_EXCEPTION:
                return "Error - stream exception";
            case error::STREAM_CONNECTION_EXPIRED:
                return "Error - stream connection expired";
            case error::CONN_CLOSE_NO_ERR:
                return "No error - closing connection";
            case error::CONN_DRAIN_NO_ERR:
                return "No error - draining connection";
            case error::CONN_WRITE_CLOSE_FAIL:
                return "Error - Failed to write connection close";
            default:
                return "Unknown error";
        }
    }

    struct io_error
    {
      private:
        uint64_t _code{0};
        bool _is_ngtcp2 = false;

      public:
        io_error() = default;
        explicit io_error(int e) : _code{static_cast<uint64_t>(e)} { _is_ngtcp2 = true; }
        explicit io_error(uint64_t e) : _code{e} { _is_ngtcp2 = false; }
        explicit io_error(error e) : _code{static_cast<uint64_t>(e)} {}

        uint64_t code() const { return _code; }

        int ngtcp2_code() const { return static_cast<int>(_code); }

        uint64_t ngtcp2() const
        {
            if (not _is_ngtcp2)
                log::info(log_cat, "Error code {} is not an ngtcp2 error code", _code);
            return _code;
        }

        const char* strerror() const
        {
            if (_is_ngtcp2)
                return ngtcp2_strerror(_code);
            else
                return quic_strerror(_code);
        }
    };

}  // namespace oxen::quic
