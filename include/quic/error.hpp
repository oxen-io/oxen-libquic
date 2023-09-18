#pragma once

#include "utils.hpp"

namespace oxen::quic
{
    constexpr uint64_t LIBQUIC_ERROR_BASE = 0x6c696271756963;  // "libquic"

    enum class error : uint64_t {
        NO_ERR = 0,

        CONN_WRITE_CLOSE_FAIL = LIBQUIC_ERROR_BASE,
        CONN_SEND_CLOSE_FAIL = LIBQUIC_ERROR_BASE + 1,

        STREAM_EXCEPTION = LIBQUIC_ERROR_BASE + 32,
        STREAM_CONNECTION_EXPIRED = LIBQUIC_ERROR_BASE + 33,

        DATAGRAM_EXCEPTION = LIBQUIC_ERROR_BASE + 64
    };

    inline const char* quic_strerror(uint64_t e)
    {
        switch (static_cast<error>(e))
        {
            case error::NO_ERR:
                return "No error";
            case error::DATAGRAM_EXCEPTION:
                return "Error - datagram exception";
            case error::STREAM_EXCEPTION:
                return "Error - stream exception";
            case error::STREAM_CONNECTION_EXPIRED:
                return "Error - stream connection expired";
            case error::CONN_WRITE_CLOSE_FAIL:
                return "Error - Failed to write connection close";
            case error::CONN_SEND_CLOSE_FAIL:
                return "Error - Failed to send connection close";
            default:
                return "Application-Specified Error";
        }
    }

    struct io_error
    {
      private:
        uint64_t _code{0};

      public:
        bool is_ngtcp2 = false;

        io_error() = default;
        explicit io_error(int e) : _code{static_cast<uint64_t>(e)} { is_ngtcp2 = true; }
        explicit io_error(uint64_t e) : _code{e} { is_ngtcp2 = false; }
        explicit io_error(error e) : _code{static_cast<uint64_t>(e)} {}

        uint64_t code() const { return _code; }

        int ngtcp2_code() const { return static_cast<int>(_code); }

        uint64_t ngtcp2() const
        {
            if (not is_ngtcp2)
                log::info(log_cat, "Error code {} is not an ngtcp2 error code", _code);
            return _code;
        }

        const char* strerror() const
        {
            if (is_ngtcp2)
                return ngtcp2_strerror(_code);
            else
                return quic_strerror(_code);
        }
    };

}  // namespace oxen::quic
